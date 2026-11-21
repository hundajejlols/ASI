"""
Serwis chunkowania dużych sieci CIDR (>10 000 IP -> adaptacyjne podgrupy /24../28)
oraz orkiestracji start/resume/cancel/reprobe przebiegów skanów przez kolejkę Redis.
"""

from datetime import datetime, timedelta, timezone
import ipaddress
import math
import re
from typing import Any
from uuid import UUID, uuid4

import redis
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import CustomSignature, Host, ScanChunk, ScanProfile, ScanRun, Target, TargetGroup
from app.schemas.contract import ScanJobChunk, ScanProfilePayload, SignatureRulePayload
from app.services.seed import ensure_default_group_and_profile

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
PORTS_SPEC_RE = re.compile(r"^(top-1000|[0-9,\-TU:]+)$")

ALLOWED_NMAP_NOARG_FLAGS = {
    "-sT", "-sS", "-sV", "-sU", "-sn", "-Pn", "-n", "-R", "-6", "-F",
    "--open", "--version-light", "--defeat-rst-ratelimit",
    "-T0", "-T1", "-T2", "-T3", "-T4",
}
ALLOWED_NMAP_VALUE_FLAGS: dict[str, re.Pattern[str]] = {
    "--max-retries": re.compile(r"^[0-5]$"),
    "--version-intensity": re.compile(r"^[0-5]$"),
    "--max-rate": re.compile(r"^[1-9][0-9]{0,4}$"),
    "--min-rate": re.compile(r"^[1-9][0-9]{0,4}$"),
    "--host-timeout": re.compile(r"^[1-9][0-9]{0,3}(ms|s|m)$"),
    "--top-ports": re.compile(r"^[1-9][0-9]{0,3}$"),
    "--max-rtt-timeout": re.compile(r"^[1-9][0-9]{0,4}(ms|s)$"),
    "--initial-rtt-timeout": re.compile(r"^[1-9][0-9]{0,4}(ms|s)$"),
}

BLOCKED_INTERNAL_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "postgres",
    "asi_postgres",
    "redis",
    "asi_redis",
    "backend",
    "asi_backend",
    "frontend",
    "asi_frontend",
    "metadata.google.internal",
}

BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]


def validate_nmap_flags(raw_flags: str) -> str:
    """Waliduje flagi nmap względem ścisłej białej listy (ochrona przed flag-injection / --script / -oN)."""
    tokens = (raw_flags or "").strip().split()
    out: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ALLOWED_NMAP_NOARG_FLAGS:
            out.append(tok)
            i += 1
            continue
        if "=" in tok:
            flag, val = tok.split("=", 1)
            pat = ALLOWED_NMAP_VALUE_FLAGS.get(flag)
            if not pat or not pat.match(val):
                raise ValueError(f"Niedozwolona flaga lub wartość nmap: {tok!r}")
            out.extend([flag, val])
            i += 1
            continue
        if tok in ALLOWED_NMAP_VALUE_FLAGS:
            if i + 1 >= len(tokens):
                raise ValueError(f"Flaga nmap {tok!r} wymaga podania wartości.")
            val = tokens[i + 1]
            if not ALLOWED_NMAP_VALUE_FLAGS[tok].match(val):
                raise ValueError(f"Nieprawidłowa wartość {val!r} dla flagi nmap {tok!r}")
            out.extend([tok, val])
            i += 2
            continue
        raise ValueError(f"Niedozwolona flaga nmap (zablokowana przez białą listę): {tok!r}")
    return " ".join(out)


def validate_ports_spec(raw_ports: str) -> str:
    """
    Waliduje specyfikację portów dla nmap (np. '80,443,8080,8443,22', '1-1024' lub 'top-1000').
    Chroni przed wstrzyknięciem dodatkowych flag CLI.
    """
    cleaned = re.sub(r"\s+", "", raw_ports.strip())
    if not cleaned:
        raise ValueError("Pusta specyfikacja portów.")
    if cleaned == "top-1000":
        return cleaned
    if not PORTS_SPEC_RE.match(cleaned):
        raise ValueError(
            f"Nieprawidłowa specyfikacja portów (dozwolone numery 1-65535, zakresy np. 1-1024 lub 'top-1000'): {raw_ports!r}"
        )
    for token in cleaned.split(","):
        part = token.lstrip("TU:")
        if not part:
            raise ValueError(f"Nieprawidłowy element na liście portów: {raw_ports!r}")
        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2 or not bounds[0].isdigit() or not bounds[1].isdigit():
                raise ValueError(f"Nieprawidłowy zakres portów: {token!r}")
            low, high = int(bounds[0]), int(bounds[1])
            if not (1 <= low <= high <= 65535):
                raise ValueError(f"Zakres portów poza przedziałem 1-65535: {token!r}")
        else:
            if not part.isdigit() or not (1 <= int(part) <= 65535):
                raise ValueError(f"Numer portu poza przedziałem 1-65535: {token!r}")
    return cleaned


def _count_ports_in_spec(ports_spec: str) -> int:
    if ports_spec == "top-1000":
        return 1000
    total = 0
    for token in ports_spec.split(","):
        part = token.lstrip("TU:")
        if "-" in part:
            lo, hi = part.split("-", 1)
            total += max(1, int(hi) - int(lo) + 1)
        elif part.isdigit():
            total += 1
    return max(1, total)


def _check_network_allowed(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> None:
    for blocked in BLOCKED_NETWORKS:
        if net.version == blocked.version and net.overlaps(blocked):
            raise ValueError(
                f"Cel {net} nakłada się na zablokowany zakres wewnętrzny/loopback/metadata ({blocked})."
            )


def detect_target_type(raw_value: str) -> tuple[str, str]:
    """
    Waliduje i klasyfikuje cel jako 'ip', 'cidr' lub 'domain' z ochroną przed celami loopback/metadata/internal.
    Zwraca (znormalizowana_wartość, typ).
    """
    val = raw_value.strip()
    if not val:
        raise ValueError("Pusty cel skanowania.")
    if val.startswith("-"):
        raise ValueError(f"Niedozwolony cel zaczynający się od '-': {raw_value!r}")

    lower_val = val.lower()
    if lower_val in BLOCKED_INTERNAL_HOSTNAMES:
        raise ValueError(f"Zablokowany wewnętrzny host infrastruktury: {raw_value!r}")

    if "/" in val:
        net = ipaddress.ip_network(val, strict=False)
        _check_network_allowed(net)
        return str(net), "cidr"

    try:
        ip = ipaddress.ip_address(val)
        _check_network_allowed(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False))
        return str(ip), "ip"
    except ValueError as exc:
        if "zablokowany zakres" in str(exc):
            raise

    if DOMAIN_RE.match(val):
        if lower_val in BLOCKED_INTERNAL_HOSTNAMES or lower_val.endswith(".localhost"):
            raise ValueError(f"Zablokowana wewnętrzna domena: {raw_value!r}")
        return lower_val, "domain"

    raise ValueError(f"Nieprawidłowy format celu (oczekiwano IP, CIDR lub domeny): {raw_value!r}")


def collapse_and_split_targets(
    typed_targets: list[tuple[str, str]],
    chunk_prefix: int = 24,
) -> tuple[list[str], int]:
    """
    Deduplikuje i scala nakładające się zakresy IPv4/IPv6 (eliminacja wyścigów i dublowania skanów),
    a następnie dzieli duże podsieci na paczki o masce `chunk_prefix`.
    Zwraca (lista_paczek, łączna_liczba_adresów_IP).
    """
    v4_nets: list[ipaddress.IPv4Network] = []
    v6_nets: list[ipaddress.IPv6Network] = []
    domains: list[str] = []

    for raw_val, ttype in typed_targets:
        if ttype == "domain":
            domains.append(raw_val.lower())
        elif ttype == "ip":
            ip_obj = ipaddress.ip_address(raw_val)
            if ip_obj.version == 4:
                v4_nets.append(ipaddress.IPv4Network(f"{ip_obj}/32", strict=False))
            else:
                v6_nets.append(ipaddress.IPv6Network(f"{ip_obj}/128", strict=False))
        else:
            net = ipaddress.ip_network(raw_val, strict=False)
            if net.version == 4:
                v4_nets.append(net)
            else:
                v6_nets.append(net)

    chunks: list[str] = []
    total_ips = 0

    for net4 in ipaddress.collapse_addresses(v4_nets):
        total_ips += net4.num_addresses
        if net4.prefixlen == 32:
            chunks.append(str(net4.network_address))
        elif net4.prefixlen < chunk_prefix:
            chunks.extend(str(sub) for sub in net4.subnets(new_prefix=chunk_prefix))
        else:
            chunks.append(str(net4))

    for net6 in ipaddress.collapse_addresses(v6_nets):
        total_ips += min(net6.num_addresses, 65536)
        if net6.prefixlen == 128:
            chunks.append(str(net6.network_address))
        else:
            chunks.append(str(net6))

    for dom in dict.fromkeys(domains):
        total_ips += 1
        chunks.append(dom)

    return list(dict.fromkeys(chunks)), total_ips


def split_target_to_chunks(raw_value: str, target_type: str, chunk_prefix: int = 24) -> list[str]:
    """Kompatybilny wrapper dla pojedynczego celu."""
    chunks, _ = collapse_and_split_targets([(raw_value, target_type)], chunk_prefix=chunk_prefix)
    return chunks


def measure_historical_ips_per_sec(db: Session, rate_limit_pps: int, ports_spec: str) -> tuple[float, str]:
    """
    Oblicza rzeczywistą średnią szybkość skanowania (IP/s) z ostatnich ukończonych paczek w DB.
    Gdy brak próbek historycznych, wyznacza bezpieczną estymację z `rate_limit_pps` i liczby portów.
    """
    recent_chunks = db.execute(
        select(ScanChunk)
        .where(
            ScanChunk.status == "completed",
            ScanChunk.started_at.is_not(None),
            ScanChunk.finished_at.is_not(None),
        )
        .order_by(desc(ScanChunk.finished_at))
        .limit(20)
    ).scalars().all()

    total_ips = 0
    total_secs = 0.0
    for ch in recent_chunks:
        try:
            net = ipaddress.ip_network(ch.target_cidr, strict=False)
            num_ips = min(net.num_addresses, 4096)
        except ValueError:
            num_ips = 1
        secs = (ch.finished_at - ch.started_at).total_seconds() if (ch.finished_at and ch.started_at) else 0.0
        if secs >= 0.5:
            total_ips += num_ips
            total_secs += secs

    if total_ips >= 8 and total_secs >= 2.0:
        return round(max(0.2, total_ips / total_secs), 2), "measured_history"

    port_cnt = _count_ports_in_spec(ports_spec)
    # Konserwatywna estymacja: pps / (porty * 2 retransmisje + narzut HTTP/TLS)
    est = max(0.5, min(60.0, rate_limit_pps / float(port_cnt * 3 + 10)))
    return round(est, 2), "rate_limit_estimate"


def compute_adaptive_chunk_prefix(
    db: Session,
    *,
    rate_limit_pps: int,
    ports_spec: str,
    window_minutes: int,
    default_prefix: int = 24,
) -> tuple[int, float, str]:
    """
    Adaptacyjnie dobiera optymalną maskę paczki CIDR (/24../28) w zależności od zmierzonej szybkości
    skanowania oraz długości okna czasowego — tak, aby pojedyncza paczka kończyła się w ~15–20% okna
    (lub maks. ~5 minut), minimalizując stratę pracy przy pauzowaniu okna.
    """
    ips_per_sec, speed_source = measure_historical_ips_per_sec(db, rate_limit_pps, ports_spec)
    target_chunk_seconds = max(30.0, min(300.0, window_minutes * 60.0 * 0.25))
    ideal_ips_per_chunk = max(16.0, min(256.0, ips_per_sec * target_chunk_seconds))

    # Dobieramy największą maskę potęgi 2 mieszczącą się w ideal_ips_per_chunk (zakres /24.. /28)
    bits_needed = max(4, min(8, int(math.floor(math.log2(ideal_ips_per_chunk)))))
    chosen_prefix = max(default_prefix, 32 - bits_needed)
    chosen_prefix = max(24, min(28, chosen_prefix))
    return chosen_prefix, ips_per_sec, speed_source


def reconcile_stale_scan_runs(db: Session, grace_seconds: int = 60) -> int:
    """
    Wykrywa osierocone przebiegi skanów (queued/running po wygaśnięciu window_deadline_at + grace),
    przełącza je na `paused_window`, a niedokończone paczki na `requeued_window` (gotowe do wznowienia).
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=grace_seconds)
    stale_runs = db.execute(
        select(ScanRun).where(
            ScanRun.status.in_(["queued", "running"]),
            ScanRun.window_deadline_at.is_not(None),
            ScanRun.window_deadline_at < cutoff,
        )
    ).scalars().all()

    reconciled = 0
    for run in stale_runs:
        chunks = db.execute(select(ScanChunk).where(ScanChunk.scan_run_id == run.id)).scalars().all()
        completed = sum(1 for c in chunks if c.status == "completed")
        run.completed_chunks = completed
        if run.total_chunks > 0 and completed >= run.total_chunks:
            run.status = "completed"
            run.finished_at = now
        else:
            for ch in chunks:
                if ch.status in ("pending", "in_progress"):
                    ch.status = "requeued_window"
                    ch.error_message = "Okno czasowe wygasło przed ukończeniem paczki (auto-reconcile)."
            run.status = "paused_window"
            run.paused_at = now
        reconciled += 1

    if reconciled:
        db.commit()
    return reconciled


def load_active_signatures(db: Session) -> list[SignatureRulePayload]:
    rows = db.execute(
        select(CustomSignature).where(CustomSignature.is_enabled.is_(True))
    ).scalars().all()
    return [
        SignatureRulePayload(
            id=sig.id,
            name=sig.name,
            severity=sig.severity,
            match_type=sig.match_type,
            pattern=sig.pattern,
            probe_path=sig.probe_path,
            expected_status=sig.expected_status,
        )
        for sig in rows
    ]


def build_profile_payload(
    profile: ScanProfile,
    rate_limit_override: int | None = None,
    ports_override: str | None = None,
) -> ScanProfilePayload:
    effective_ports = validate_ports_spec(ports_override) if (ports_override and ports_override.strip()) else validate_ports_spec(profile.ports)
    safe_flags = validate_nmap_flags(profile.nmap_flags)
    return ScanProfilePayload(
        nmap_flags=safe_flags,
        ports=effective_ports,
        rate_limit_pps=rate_limit_override or profile.rate_limit_pps,
        http_fingerprint_enabled=profile.http_fingerprint_enabled,
        signatures_enabled=profile.signatures_enabled,
    )


def start_scan_run(
    db: Session,
    *,
    schedule_id: UUID | None = None,
    target_group_id: UUID | None = None,
    raw_targets: list[str] | None = None,
    profile_id: UUID | None = None,
    chunk_prefix_override: int | None = None,
    adaptive_chunking: bool = False,
    rate_limit_pps: int | None = None,
    ports_override: str | None = None,
    window_minutes: int = 60,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Tworzy przebieg skanu, scala nakładające się zakresy CIDR, dzieli na paczki (statycznie lub adaptacyjnie),
    zapisuje scan_runs + scan_chunks i kolejkuje paczki w Redis z window_deadline_utc i aktywnymi sygnaturami.
    """
    default_group, default_profile = ensure_default_group_and_profile(db)
    group = db.get(TargetGroup, target_group_id) if target_group_id is not None else default_group
    if group is None:
        raise ValueError("Nie znaleziono grupy celów (target_groups).")

    profile = db.get(ScanProfile, profile_id) if profile_id is not None else default_profile
    if profile is None:
        raise ValueError("Nie znaleziono profilu skanowania (scan_profiles).")

    profile_payload = build_profile_payload(
        profile,
        rate_limit_override=rate_limit_pps,
        ports_override=ports_override,
    )

    if adaptive_chunking or chunk_prefix_override is None:
        adapt_prefix, ips_per_sec, speed_source = compute_adaptive_chunk_prefix(
            db,
            rate_limit_pps=profile_payload.rate_limit_pps,
            ports_spec=profile_payload.ports,
            window_minutes=window_minutes,
            default_prefix=profile.chunk_cidr_prefix or 24,
        )
        chunk_prefix = adapt_prefix if adaptive_chunking else (profile.chunk_cidr_prefix or 24)
    else:
        chunk_prefix = chunk_prefix_override
        ips_per_sec, speed_source = measure_historical_ips_per_sec(
            db, profile_payload.rate_limit_pps, profile_payload.ports
        )

    typed_targets: list[tuple[str, str]] = []
    if raw_targets:
        for item in raw_targets:
            typed_targets.append(detect_target_type(item))
    else:
        db_targets = db.execute(
            select(Target).where(Target.group_id == group.id, Target.is_active.is_(True))
        ).scalars().all()
        for t in db_targets:
            typed_targets.append(detect_target_type(t.raw_value))

    chunk_targets, total_ips = collapse_and_split_targets(typed_targets, chunk_prefix=chunk_prefix)
    if not chunk_targets:
        raise ValueError("Brak celów do przeskanowania (dodaj cele w /api/v1/targets lub podaj raw_targets).")

    estimated_duration_sec = round(max(1.0, total_ips / max(0.2, ips_per_sec)), 1)
    deadline = datetime.now(timezone.utc) + timedelta(minutes=window_minutes)
    signatures = load_active_signatures(db) if profile.signatures_enabled else []

    if dry_run:
        return {
            "dry_run": True,
            "target_group_id": str(group.id),
            "profile": profile.name,
            "ports": profile_payload.ports,
            "chunk_cidr_prefix": chunk_prefix,
            "adaptive_chunking": adaptive_chunking,
            "measured_ips_per_sec": ips_per_sec,
            "speed_source": speed_source,
            "total_target_ips": total_ips,
            "estimated_duration_seconds": estimated_duration_sec,
            "fits_in_window": estimated_duration_sec <= (window_minutes * 60),
            "rate_limit_pps": profile_payload.rate_limit_pps,
            "window_deadline_utc": deadline.isoformat(),
            "active_signatures_count": len(signatures),
            "total_chunks": len(chunk_targets),
            "chunks": chunk_targets,
        }

    scan_run_id = uuid4()
    scan_run = ScanRun(
        id=scan_run_id,
        schedule_id=schedule_id,
        target_group_id=group.id,
        profile_id=profile.id,
        status="queued",
        window_deadline_at=deadline,
        total_chunks=len(chunk_targets),
        completed_chunks=0,
    )
    db.add(scan_run)

    chunk_models: list[ScanChunk] = []
    for cidr in chunk_targets:
        chunk_model = ScanChunk(
            id=uuid4(),
            scan_run_id=scan_run_id,
            target_cidr=cidr,
            status="pending",
        )
        db.add(chunk_model)
        chunk_models.append(chunk_model)

    db.commit()

    try:
        rdb = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=3)
        pipe = rdb.pipeline()
        for chunk_model in chunk_models:
            job = ScanJobChunk(
                scan_run_id=scan_run_id,
                chunk_id=chunk_model.id,
                target_cidr=chunk_model.target_cidr,
                window_deadline_utc=deadline,
                profile=profile_payload,
                signatures=signatures,
            )
            pipe.rpush(settings.redis_job_queue, job.model_dump_json())
        pipe.execute()
    except redis.RedisError as exc:
        now_err = datetime.now(timezone.utc)
        scan_run.status = "failed"
        scan_run.finished_at = now_err
        for cm in chunk_models:
            cm.status = "failed"
            cm.error_message = f"Redis unavailable: {exc}"
        db.commit()
        raise RuntimeError(f"Kolejka Redis jest niedostępna — nie udało się zakolejkować skanu: {exc}") from exc

    return {
        "dry_run": False,
        "queued": True,
        "scan_run_id": str(scan_run_id),
        "status": "queued",
        "ports": profile_payload.ports,
        "chunk_cidr_prefix": chunk_prefix,
        "adaptive_chunking": adaptive_chunking,
        "measured_ips_per_sec": ips_per_sec,
        "estimated_duration_seconds": estimated_duration_sec,
        "window_deadline_utc": deadline.isoformat(),
        "rate_limit_pps": profile_payload.rate_limit_pps,
        "active_signatures_count": len(signatures),
        "total_chunks": len(chunk_models),
        "chunks": [c.target_cidr for c in chunk_models],
    }


def resume_scan_run(
    db: Session,
    *,
    scan_run_id: UUID,
    window_minutes: int = 60,
    rate_limit_pps: int | None = None,
    ports_override: str | None = None,
) -> dict[str, Any]:
    """
    Wznawia przerwany lub nieukończony skan (np. po przekroczeniu okna czasowego).
    """
    reconcile_stale_scan_runs(db)
    scan_run = db.get(ScanRun, scan_run_id)
    if scan_run is None:
        raise LookupError("Nie znaleziono scan_run o podanym ID.")

    if scan_run.status in ("queued", "running"):
        raise ValueError(
            f"Skan ma obecnie status '{scan_run.status}' — nie można wznowić aktywnego przebiegu (anuluj go najpierw lub poczekaj na koniec okna)."
        )
    if scan_run.status in ("completed", "cancelled"):
        raise ValueError(f"Skan jest już zakończony (status '{scan_run.status}') i nie wymaga wznowienia.")

    profile = db.get(ScanProfile, scan_run.profile_id)
    if profile is None:
        raise ValueError("Brak profilu skanowania powiązanego z tym scan_run.")

    now_utc = datetime.now(timezone.utc)
    if scan_run.window_deadline_at and scan_run.window_deadline_at > now_utc:
        requeue_statuses = ["requeued_window", "failed"]
    else:
        requeue_statuses = ["requeued_window", "pending", "failed", "in_progress"]

    unfinished_chunks = db.execute(
        select(ScanChunk).where(
            ScanChunk.scan_run_id == scan_run_id,
            ScanChunk.status.in_(requeue_statuses),
        )
    ).scalars().all()

    if not unfinished_chunks:
        return {
            "resumed": False,
            "scan_run_id": str(scan_run_id),
            "status": scan_run.status,
            "requeued_chunks": 0,
            "message": "Brak niedokończonych paczek (requeued_window/pending) do wznowienia.",
        }

    prev_status = scan_run.status
    prev_deadline = scan_run.window_deadline_at
    prev_paused_at = scan_run.paused_at
    prev_chunk_states = [(ch, ch.status, ch.error_message) for ch in unfinished_chunks]

    new_deadline = now_utc + timedelta(minutes=window_minutes)
    scan_run.status = "running"
    scan_run.window_deadline_at = new_deadline
    scan_run.paused_at = None

    for ch in unfinished_chunks:
        ch.status = "pending"
        ch.error_message = None

    db.commit()

    signatures = load_active_signatures(db) if profile.signatures_enabled else []
    profile_payload = build_profile_payload(
        profile,
        rate_limit_override=rate_limit_pps,
        ports_override=ports_override,
    )

    try:
        rdb = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=3)
        pipe = rdb.pipeline()
        for ch in unfinished_chunks:
            job = ScanJobChunk(
                scan_run_id=scan_run_id,
                chunk_id=ch.id,
                target_cidr=ch.target_cidr,
                window_deadline_utc=new_deadline,
                profile=profile_payload,
                signatures=signatures,
            )
            pipe.rpush(settings.redis_job_queue, job.model_dump_json())
        pipe.execute()
    except redis.RedisError as exc:
        scan_run.status = prev_status
        scan_run.window_deadline_at = prev_deadline
        scan_run.paused_at = prev_paused_at
        for ch, old_st, old_err in prev_chunk_states:
            ch.status = old_st
            ch.error_message = old_err
        db.commit()
        raise RuntimeError(f"Kolejka Redis jest niedostępna — nie udało się wznowić skanu: {exc}") from exc

    return {
        "resumed": True,
        "scan_run_id": str(scan_run_id),
        "status": scan_run.status,
        "ports": profile_payload.ports,
        "window_deadline_utc": new_deadline.isoformat(),
        "requeued_chunks": len(unfinished_chunks),
        "chunks": [c.target_cidr for c in unfinished_chunks],
    }


def cancel_scan_run(db: Session, *, scan_run_id: UUID) -> dict[str, Any]:
    """Anuluje aktywny lub zapauzowany przebieg skanu i oznacza niedokończone paczki jako failed/cancelled."""
    scan_run = db.get(ScanRun, scan_run_id)
    if scan_run is None:
        raise LookupError("Nie znaleziono scan_run o podanym ID.")
    if scan_run.status in ("completed", "cancelled"):
        raise ValueError(f"Skan ma już status '{scan_run.status}'.")

    now = datetime.now(timezone.utc)
    scan_run.status = "cancelled"
    scan_run.finished_at = now
    unfinished = db.execute(
        select(ScanChunk).where(
            ScanChunk.scan_run_id == scan_run_id,
            ScanChunk.status.in_(["pending", "in_progress", "requeued_window"]),
        )
    ).scalars().all()
    for ch in unfinished:
        ch.status = "failed"
        ch.error_message = "Anulowano przez operatora."
        ch.finished_at = now
    db.commit()
    return {
        "cancelled": True,
        "scan_run_id": str(scan_run_id),
        "status": "cancelled",
        "cancelled_chunks": len(unfinished),
    }


def reprobe_unstable_hosts(db: Session, *, window_minutes: int = 15) -> dict[str, Any]:
    """Uruchamia celowany powtórny pomiar wyłącznie dla hostów o statusie 'unstable'."""
    unstable_hosts = db.execute(select(Host).where(Host.status == "unstable")).scalars().all()
    if not unstable_hosts:
        return {
            "queued": False,
            "unstable_hosts_count": 0,
            "message": "Brak niestabilnych hostów (status='unstable') wymagających powtórnego pomiaru.",
        }
    ips = [str(h.ip_address).split("/")[0] for h in unstable_hosts]
    res = start_scan_run(
        db,
        raw_targets=ips,
        window_minutes=window_minutes,
        dry_run=False,
    )
    res["unstable_hosts_count"] = len(ips)
    return res
