"""
Wspólny serwis przetwarzania wyników skanów (ingest_scan_result).
Obsługuje:
  - aktualizację statusu scan_chunks i scan_runs (completed / requeued_window / failed),
  - upsert hosts, services, http_fingerprints (z szyfrowaniem AES-256-GCM + AAD nagłówków i ciasteczek),
  - próg missed_scans dla hostów niestabilnych (online -> unstable -> offline),
  - silnik Diff generujący zdarzenia change_events,
  - pełną izolację od asset_overrides (nigdy nie nadpisuje ręcznych korekt).
"""

from datetime import datetime, timezone
import ipaddress
import re
from typing import Any
from uuid import UUID

from sqlalchemy import cast, desc, func, select
from sqlalchemy.dialects.postgresql import CIDR, INET
from sqlalchemy.orm import Session

from app.core.crypto import AAD_HTTP_COOKIES, AAD_HTTP_HEADERS, encrypt_json
from app.db.models import (
    ChangeEvent,
    CustomSignature,
    Host,
    HTTPFingerprint,
    ScanChunk,
    ScanRun,
    Service,
    SignatureMatch,
)
from app.schemas.contract import HTTPFingerprintResult, ScanChunkResult, SignatureMatchResult
from app.services.seed import ensure_default_group_and_profile


DEFAULT_MISSED_SCANS_THRESHOLD = 3
MAX_REGEX_LEN = 256
UNSAFE_PYTHON_REGEX_MARKERS = ("(?=", "(?!", "(?<=", "(?<!")


def _ensure_scan_run(db: Session, scan_run_id: UUID, now: datetime) -> ScanRun:
    """Zwraca istniejący ScanRun lub tworzy rekord ad-hoc (gwarantując grupę i profil nawet na pustej bazie)."""
    scan_run = db.get(ScanRun, scan_run_id)
    if scan_run is not None:
        return scan_run

    group, profile = ensure_default_group_and_profile(db)
    scan_run = ScanRun(
        id=scan_run_id,
        target_group_id=group.id,
        profile_id=profile.id,
        status="running",
        total_chunks=1,
        completed_chunks=0,
        started_at=now,
    )
    db.add(scan_run)
    db.flush()
    return scan_run


def _safe_compile_regex(pattern: str) -> re.Pattern[str] | None:
    if not pattern or len(pattern) > MAX_REGEX_LEN:
        return None
    if any(m in pattern for m in UNSAFE_PYTHON_REGEX_MARKERS):
        return None
    try:
        return re.compile(pattern)
    except re.error:
        return None


def _evaluate_passive_signatures_on_http(
    db: Session,
    fp: HTTPFingerprintResult,
) -> list[SignatureMatchResult]:
    """
    Pasywna ewaluacja aktywnych sygnatur (header, cookie, favicon_hash) bez zapytań sieciowych —
    używana dla danych wprowadzanych ręcznie (POST /scans/manual) oraz importu JSON/CSV,
    aby podlegały temu samemu przetwarzaniu co wyniki ze skanera Go.
    """
    if not (fp.headers or fp.cookies or fp.favicon_mmh3_hash):
        return []

    rules = db.execute(
        select(CustomSignature).where(
            CustomSignature.is_enabled.is_(True),
            CustomSignature.match_type.in_(["header", "cookie", "favicon_hash"]),
        )
    ).scalars().all()

    matches: list[SignatureMatchResult] = []
    for sig in rules:
        if sig.match_type == "header" and fp.headers:
            regex = _safe_compile_regex(sig.pattern)
            if regex is None:
                continue
            for k, v in fp.headers.items():
                line = f"{k}: {v}"
                if regex.search(line[:2048]):
                    matches.append(
                        SignatureMatchResult(
                            signature_id=sig.id,
                            signature_name=sig.name,
                            evidence=line,
                        )
                    )
                    break
        elif sig.match_type == "cookie" and fp.cookies:
            pat = sig.pattern.lower()
            for cookie_name in fp.cookies:
                if pat in str(cookie_name).lower():
                    matches.append(
                        SignatureMatchResult(
                            signature_id=sig.id,
                            signature_name=sig.name,
                            evidence=f"cookie={cookie_name}",
                        )
                    )
                    break
        elif sig.match_type == "favicon_hash" and fp.favicon_mmh3_hash:
            if fp.favicon_mmh3_hash == sig.pattern:
                matches.append(
                    SignatureMatchResult(
                        signature_id=sig.id,
                        signature_name=sig.name,
                        evidence=f"favicon_mmh3={fp.favicon_mmh3_hash}",
                    )
                )
    return matches


def _diff_http_fingerprint(
    prev_fp: HTTPFingerprint,
    curr_fp: HTTPFingerprint,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Porównuje istotne atrybuty fingerprintu HTTP/TLS i zwraca (previous, current) różnic."""
    prev_diff: dict[str, Any] = {}
    curr_diff: dict[str, Any] = {}

    if prev_fp.status_code != curr_fp.status_code:
        prev_diff["status_code"] = prev_fp.status_code
        curr_diff["status_code"] = curr_fp.status_code

    if (prev_fp.title or "") != (curr_fp.title or ""):
        prev_diff["title"] = prev_fp.title
        curr_diff["title"] = curr_fp.title

    prev_tech = sorted(set(prev_fp.technologies or []))
    curr_tech = sorted(set(curr_fp.technologies or []))
    if prev_tech != curr_tech:
        prev_diff["technologies"] = prev_tech
        curr_diff["technologies"] = curr_tech

    curr_tls_not_after = curr_fp.tls_not_after.isoformat() if curr_fp.tls_not_after else None
    prev_tls_not_after = prev_fp.tls_not_after.isoformat() if prev_fp.tls_not_after else None

    if (
        prev_fp.tls_subject != curr_fp.tls_subject
        or prev_fp.tls_issuer != curr_fp.tls_issuer
        or prev_tls_not_after != curr_tls_not_after
    ):
        prev_diff["tls"] = {
            "subject": prev_fp.tls_subject,
            "issuer": prev_fp.tls_issuer,
            "not_after": prev_tls_not_after,
        }
        curr_diff["tls"] = {
            "subject": curr_fp.tls_subject,
            "issuer": curr_fp.tls_issuer,
            "not_after": curr_tls_not_after,
        }

    if prev_fp.is_admin_panel != curr_fp.is_admin_panel:
        prev_diff["is_admin_panel"] = prev_fp.is_admin_panel
        curr_diff["is_admin_panel"] = curr_fp.is_admin_panel

    if prev_fp.is_staging_env != curr_fp.is_staging_env:
        prev_diff["is_staging_env"] = prev_fp.is_staging_env
        curr_diff["is_staging_env"] = curr_fp.is_staging_env

    if (prev_fp.probe_error or "") != (curr_fp.probe_error or ""):
        prev_diff["probe_error"] = prev_fp.probe_error
        curr_diff["probe_error"] = curr_fp.probe_error

    # Detekcja istotnej zmiany opóźnienia odpowiedzi (np. Toxiproxy latency / degradacja usługi)
    if prev_fp.response_time_ms is not None and curr_fp.response_time_ms is not None:
        p_ms = int(prev_fp.response_time_ms)
        c_ms = int(curr_fp.response_time_ms)
        if abs(c_ms - p_ms) >= 250 and max(c_ms, p_ms) >= max(int(min(c_ms, p_ms) * 2.5), 400):
            prev_diff["response_time_ms"] = p_ms
            curr_diff["response_time_ms"] = c_ms

    return prev_diff, curr_diff


def ingest_scan_result(
    db: Session,
    payload: ScanChunkResult,
    target_cidr: str | None = None,
    missed_scans_threshold: int | None = None,
    is_partial: bool | None = None,
) -> dict[str, Any]:
    """
    Przetwarza wynik paczki skanu (lub importu CSV/JSON/formularza ręcznego), aktualizuje stan zasobów
    i generuje zdarzenia Diff (change_events).
    """
    now = datetime.now(timezone.utc)
    scan_run = _ensure_scan_run(db, payload.scan_run_id, now)
    chunk = db.get(ScanChunk, payload.chunk_id)

    effective_cidr = target_cidr or (chunk.target_cidr if chunk else None)
    threshold = missed_scans_threshold
    if threshold is None:
        if scan_run.schedule and scan_run.schedule.missed_scans_threshold:
            threshold = scan_run.schedule.missed_scans_threshold
        else:
            threshold = DEFAULT_MISSED_SCANS_THRESHOLD

    up_hosts = [h for h in payload.hosts if h.is_up]

    # 1. Aktualizacja statusu scan_chunks (z ochroną przed nadpisaniem już ukończonej paczki)
    if chunk is not None:
        if chunk.status == "completed" and payload.status != "completed":
            db.commit()
            return {
                "accepted": True,
                "ignored_stale": True,
                "scan_run_id": str(payload.scan_run_id),
                "chunk_id": str(payload.chunk_id),
                "status": chunk.status,
                "hosts_processed": 0,
                "changes_recorded": 0,
            }
        chunk.status = payload.status
        chunk.worker_id = payload.worker_id
        chunk.attempts = (chunk.attempts or 0) + 1
        chunk.hosts_discovered = len(up_hosts)
        chunk.started_at = payload.started_at
        chunk.finished_at = payload.finished_at
        chunk.error_message = payload.error_message
        db.flush()

    # 2. Idempotentna aktualizacja statusu scan_runs
    if scan_run.started_at is None:
        scan_run.started_at = payload.started_at

    if chunk is not None:
        completed_count = db.execute(
            select(func.count(ScanChunk.id)).where(
                ScanChunk.scan_run_id == scan_run.id,
                ScanChunk.status == "completed",
            )
        ).scalar_one()
        failed_count = db.execute(
            select(func.count(ScanChunk.id)).where(
                ScanChunk.scan_run_id == scan_run.id,
                ScanChunk.status == "failed",
            )
        ).scalar_one()
        requeued_count = db.execute(
            select(func.count(ScanChunk.id)).where(
                ScanChunk.scan_run_id == scan_run.id,
                ScanChunk.status == "requeued_window",
            )
        ).scalar_one()
        scan_run.completed_chunks = int(completed_count)
    else:
        completed_count = (
            min(scan_run.total_chunks, (scan_run.completed_chunks or 0) + 1)
            if payload.status == "completed"
            else (scan_run.completed_chunks or 0)
        )
        failed_count = 1 if payload.status == "failed" else 0
        requeued_count = 1 if payload.status == "requeued_window" else 0
        scan_run.completed_chunks = int(completed_count)

    if scan_run.status != "cancelled":
        if payload.status == "requeued_window" or (requeued_count > 0 and completed_count < scan_run.total_chunks):
            scan_run.status = "paused_window"
            scan_run.paused_at = now
        elif scan_run.total_chunks > 0 and completed_count >= scan_run.total_chunks:
            scan_run.status = "completed"
            scan_run.finished_at = now
            scan_run.paused_at = None
        elif scan_run.total_chunks > 0 and (completed_count + failed_count) >= scan_run.total_chunks and failed_count > 0:
            scan_run.status = "failed"
            scan_run.finished_at = now
        elif payload.status == "completed":
            scan_run.status = "running"

    if payload.status != "completed":
        db.commit()
        return {
            "accepted": True,
            "scan_run_id": str(payload.scan_run_id),
            "chunk_id": str(payload.chunk_id),
            "status": payload.status,
            "hosts_processed": 0,
            "changes_recorded": 0,
        }

    changes_recorded = 0
    seen_up_ips: set[str] = set()
    if is_partial is not None:
        is_partial_ingest = is_partial
    else:
        is_partial_ingest = payload.worker_id == "manual-form" or payload.worker_id.startswith("import-")
    is_active_scanner = not is_partial_ingest

    def record_change(
        *,
        host_id: UUID,
        change_type: str,
        severity: str = "info",
        service_id: UUID | None = None,
        previous_value: dict[str, Any] | None = None,
        current_value: dict[str, Any] | None = None,
    ) -> None:
        nonlocal changes_recorded
        db.add(
            ChangeEvent(
                scan_run_id=scan_run.id,
                host_id=host_id,
                service_id=service_id,
                change_type=change_type,
                severity=severity,
                previous_value=previous_value,
                current_value=current_value,
                detected_at=now,
            )
        )
        changes_recorded += 1

    # 3. Upsert odpowiadających hostów i usług
    for host_in in up_hosts:
        host_ip_obj = ipaddress.ip_address(host_in.ip)
        host_ip_str = str(host_ip_obj)
        seen_up_ips.add(host_ip_str)
        host = db.execute(
            select(Host).where(Host.ip_address == cast(host_ip_str, INET))
        ).scalar_one_or_none()

        if host is None:
            host = Host(
                ip_address=host_ip_obj,
                hostname=host_in.hostname,
                status="online",
                missed_scans=0,
                first_seen_at=now,
                last_seen_at=now,
                last_scan_run_id=scan_run.id,
            )
            db.add(host)
            db.flush()
            record_change(
                host_id=host.id,
                change_type="host_new",
                severity="info",
                current_value={"ip": host_ip_str, "hostname": host_in.hostname},
            )
        else:
            prev_status = host.status
            prev_missed = host.missed_scans
            host.status = "online"
            host.missed_scans = 0
            host.last_seen_at = now
            host.last_scan_run_id = scan_run.id
            if host_in.hostname:
                host.hostname = host_in.hostname

            if prev_status in ("offline", "unstable"):
                record_change(
                    host_id=host.id,
                    change_type="host_recovered",
                    severity="info",
                    previous_value={"status": prev_status, "missed_scans": prev_missed},
                    current_value={"status": "online", "missed_scans": 0},
                )

        existing_services_list = db.execute(
            select(Service).where(Service.host_id == host.id)
        ).scalars().all()
        existing_services = {(s.port, s.protocol): s for s in existing_services_list}
        seen_service_keys: set[tuple[int, str]] = set()

        for svc_in in host_in.services:
            key = (svc_in.port, svc_in.protocol)
            svc = existing_services.get(key)

            # Jawnie zamknięty port (TCP RST od żywego hosta) -> natychmiastowe wykrycie zamknięcia usługi
            if svc_in.state == "closed":
                if is_active_scanner and svc is not None and svc.state in ("open", "unstable"):
                    prev_state = svc.state
                    svc.state = "closed"
                    svc.missed_scans = threshold
                    seen_service_keys.add(key)
                    record_change(
                        host_id=host.id,
                        service_id=svc.id,
                        change_type="service_closed",
                        severity="low",
                        previous_value={
                            "port": svc.port,
                            "protocol": svc.protocol,
                            "service_name": svc.service_name,
                            "state": prev_state,
                        },
                        current_value={
                            "port": svc.port,
                            "protocol": svc.protocol,
                            "state": "closed",
                            "reason": "port_closed_rst",
                        },
                    )
                continue

            if svc_in.state != "open":
                continue

            seen_service_keys.add(key)

            if svc is None:
                svc = Service(
                    host_id=host.id,
                    port=svc_in.port,
                    protocol=svc_in.protocol,
                    state="open",
                    service_name=svc_in.service_name,
                    product=svc_in.product,
                    version=svc_in.version,
                    banner=svc_in.banner,
                    missed_scans=0,
                    first_seen_at=now,
                    last_seen_at=now,
                )
                db.add(svc)
                db.flush()
                record_change(
                    host_id=host.id,
                    service_id=svc.id,
                    change_type="service_new",
                    severity="low",
                    current_value={
                        "port": svc.port,
                        "protocol": svc.protocol,
                        "service_name": svc.service_name,
                        "product": svc.product,
                        "version": svc.version,
                    },
                )
            else:
                if svc.state != "open":
                    if svc.state == "closed":
                        record_change(
                            host_id=host.id,
                            service_id=svc.id,
                            change_type="service_new",
                            severity="low",
                            previous_value={"state": svc.state},
                            current_value={
                                "state": "open",
                                "reason": "service_reopened",
                                "port": svc.port,
                                "protocol": svc.protocol,
                                "service_name": svc_in.service_name,
                            },
                        )
                else:
                    prev_meta: dict[str, Any] = {}
                    curr_meta: dict[str, Any] = {}
                    for field in ("service_name", "product", "version", "banner"):
                        old_val = getattr(svc, field)
                        new_val = getattr(svc_in, field)
                        if is_partial_ingest and new_val is None:
                            continue
                        if (old_val or "") != (new_val or ""):
                            prev_meta[field] = old_val
                            curr_meta[field] = new_val
                    if prev_meta:
                        record_change(
                            host_id=host.id,
                            service_id=svc.id,
                            change_type="service_changed",
                            severity="info",
                            previous_value=prev_meta,
                            current_value=curr_meta,
                        )

                svc.state = "open"
                svc.missed_scans = 0
                svc.last_seen_at = now
                if not is_partial_ingest or svc_in.service_name is not None:
                    svc.service_name = svc_in.service_name
                if not is_partial_ingest or svc_in.product is not None:
                    svc.product = svc_in.product
                if not is_partial_ingest or svc_in.version is not None:
                    svc.version = svc_in.version
                if not is_partial_ingest or svc_in.banner is not None:
                    svc.banner = svc_in.banner

            # HTTP Fingerprint (szyfrowane AES-256-GCM + AAD dla headers_encrypted i cookies_encrypted)
            if svc_in.http is not None:
                prev_fp = db.execute(
                    select(HTTPFingerprint)
                    .where(HTTPFingerprint.service_id == svc.id)
                    .order_by(desc(HTTPFingerprint.captured_at))
                    .limit(1)
                ).scalar_one_or_none()

                headers_blob = (
                    prev_fp.headers_encrypted
                    if (is_partial_ingest and not svc_in.http.headers and prev_fp and prev_fp.headers_encrypted)
                    else encrypt_json(svc_in.http.headers, associated_data=AAD_HTTP_HEADERS)
                )
                cookies_blob = (
                    prev_fp.cookies_encrypted
                    if (is_partial_ingest and not svc_in.http.cookies and prev_fp and prev_fp.cookies_encrypted)
                    else encrypt_json(svc_in.http.cookies, associated_data=AAD_HTTP_COOKIES)
                )
                tls_subject = svc_in.http.tls.subject if svc_in.http.tls else (prev_fp.tls_subject if (is_partial_ingest and prev_fp) else None)
                tls_issuer = svc_in.http.tls.issuer if svc_in.http.tls else (prev_fp.tls_issuer if (is_partial_ingest and prev_fp) else None)
                tls_not_after = svc_in.http.tls.not_after if svc_in.http.tls else (prev_fp.tls_not_after if (is_partial_ingest and prev_fp) else None)
                tls_san = svc_in.http.tls.san if svc_in.http.tls else (list(prev_fp.tls_san or []) if (is_partial_ingest and prev_fp) else [])
                fav_hash = svc_in.http.favicon_mmh3_hash or (prev_fp.favicon_mmh3_hash if (is_partial_ingest and prev_fp) else None)
                tech_conf = dict(svc_in.http.tech_confidence or {})
                if not tech_conf and svc_in.http.technologies:
                    tech_conf = {t: "medium" for t in svc_in.http.technologies}

                new_fp = HTTPFingerprint(
                    service_id=svc.id,
                    scan_run_id=scan_run.id,
                    url=svc_in.http.url,
                    scheme=svc_in.http.scheme,
                    status_code=svc_in.http.status_code,
                    response_time_ms=svc_in.http.response_time_ms,
                    probe_error=svc_in.http.probe_error,
                    title=svc_in.http.title,
                    redirect_chain=svc_in.http.redirect_chain,
                    headers_encrypted=headers_blob,
                    cookies_encrypted=cookies_blob,
                    favicon_mmh3_hash=fav_hash,
                    tls_subject=tls_subject,
                    tls_issuer=tls_issuer,
                    tls_not_after=tls_not_after,
                    tls_san=tls_san,
                    technologies=svc_in.http.technologies,
                    tech_confidence=tech_conf,
                    is_admin_panel=svc_in.http.is_admin_panel,
                    is_staging_env=svc_in.http.is_staging_env,
                    captured_at=now,
                )
                db.add(new_fp)

                if prev_fp is not None:
                    prev_diff, curr_diff = _diff_http_fingerprint(prev_fp, new_fp)
                    if "tls" in prev_diff:
                        record_change(
                            host_id=host.id,
                            service_id=svc.id,
                            change_type="tls_changed",
                            severity="medium",
                            previous_value={"tls": prev_diff.pop("tls")},
                            current_value={"tls": curr_diff.pop("tls")},
                        )
                    if "technologies" in prev_diff:
                        record_change(
                            host_id=host.id,
                            service_id=svc.id,
                            change_type="tech_changed",
                            severity="low",
                            previous_value={"technologies": prev_diff.pop("technologies")},
                            current_value={"technologies": curr_diff.pop("technologies")},
                        )
                    if prev_diff:
                        high_latency_or_err = bool(curr_diff.get("probe_error")) or (
                            isinstance(curr_diff.get("response_time_ms"), int) and curr_diff["response_time_ms"] >= 1000
                        )
                        sev = (
                            "medium"
                            if ((svc_in.http.is_admin_panel and not prev_fp.is_admin_panel) or high_latency_or_err)
                            else "low"
                        )
                        record_change(
                            host_id=host.id,
                            service_id=svc.id,
                            change_type="service_changed",
                            severity=sev,
                            previous_value=prev_diff,
                            current_value=curr_diff,
                        )

            # Dopasowane sygnatury pasywne
            effective_sig_matches = list(svc_in.signature_matches)
            if is_partial_ingest and svc_in.http is not None:
                existing_payload_sig_ids = {m.signature_id for m in effective_sig_matches}
                for auto_match in _evaluate_passive_signatures_on_http(db, svc_in.http):
                    if auto_match.signature_id not in existing_payload_sig_ids:
                        effective_sig_matches.append(auto_match)
                        existing_payload_sig_ids.add(auto_match.signature_id)

            seen_sig_ids_in_payload: set[UUID] = set()
            for sig_in in effective_sig_matches:
                if sig_in.signature_id in seen_sig_ids_in_payload:
                    continue
                seen_sig_ids_in_payload.add(sig_in.signature_id)

                sig_def = db.get(CustomSignature, sig_in.signature_id)
                if sig_def is None:
                    continue
                existing_matches = db.execute(
                    select(SignatureMatch)
                    .where(
                        SignatureMatch.service_id == svc.id,
                        SignatureMatch.signature_id == sig_in.signature_id,
                    )
                    .order_by(desc(SignatureMatch.matched_at))
                ).scalars().all()

                if not existing_matches:
                    db.add(
                        SignatureMatch(
                            scan_run_id=scan_run.id,
                            service_id=svc.id,
                            signature_id=sig_in.signature_id,
                            matched_evidence=sig_in.evidence,
                            matched_at=now,
                        )
                    )
                    record_change(
                        host_id=host.id,
                        service_id=svc.id,
                        change_type="signature_matched",
                        severity=sig_def.severity,
                        current_value={
                            "reason": "signature_matched",
                            "signature_id": str(sig_in.signature_id),
                            "signature_name": sig_in.signature_name,
                            "evidence": sig_in.evidence,
                        },
                    )
                else:
                    primary = existing_matches[0]
                    primary.scan_run_id = scan_run.id
                    primary.matched_evidence = sig_in.evidence
                    primary.matched_at = now
                    for dup in existing_matches[1:]:
                        db.delete(dup)

            if is_active_scanner and svc_in.http is not None:
                stale_matches = db.execute(
                    select(SignatureMatch).where(SignatureMatch.service_id == svc.id)
                ).scalars().all()
                for sm in stale_matches:
                    if sm.signature_id not in seen_sig_ids_in_payload:
                        sig_def = db.get(CustomSignature, sm.signature_id)
                        if sig_def is not None and sig_def.is_enabled:
                            record_change(
                                host_id=host.id,
                                service_id=svc.id,
                                change_type="service_changed",
                                severity="info",
                                previous_value={
                                    "reason": "signature_resolved",
                                    "signature_id": str(sm.signature_id),
                                    "signature_name": sig_def.name,
                                    "evidence": sm.matched_evidence,
                                },
                                current_value={"reason": "signature_resolved", "matched": False},
                            )
                            db.delete(sm)

        # Usługi wcześniej otwarte, które nie odpowiedziały (tylko aktywny skan)
        if is_active_scanner:
            for key, svc in existing_services.items():
                if svc.state in ("open", "unstable") and key not in seen_service_keys:
                    prev_state = svc.state
                    svc.missed_scans = (svc.missed_scans or 0) + 1
                    if svc.missed_scans >= threshold:
                        svc.state = "closed"
                        record_change(
                            host_id=host.id,
                            service_id=svc.id,
                            change_type="service_closed",
                            severity="low",
                            previous_value={
                                "port": svc.port,
                                "protocol": svc.protocol,
                                "service_name": svc.service_name,
                                "state": prev_state,
                            },
                            current_value={
                                "port": svc.port,
                                "protocol": svc.protocol,
                                "state": "closed",
                                "missed_scans": svc.missed_scans,
                            },
                        )
                    else:
                        svc.state = "unstable"

    # 4. Obsługa hostów z tego samego target_cidr (lub domeny), które nie odpowiedziały (missed_scans)
    if effective_cidr and (is_active_scanner or target_cidr is not None):
        try:
            network = ipaddress.ip_network(effective_cidr, strict=False)
        except ValueError:
            network = None

        if network is not None:
            scoped_hosts = db.execute(
                select(Host).where(
                    Host.ip_address.op("<<=")(cast(str(network), CIDR)),
                    Host.status != "archived",
                )
            ).scalars().all()
        else:
            domain_clean = effective_cidr.strip().lower()
            scoped_hosts = db.execute(
                select(Host).where(
                    func.lower(Host.hostname) == domain_clean,
                    Host.status != "archived",
                )
            ).scalars().all()

        for h in scoped_hosts:
            if str(h.ip_address).split("/")[0] in seen_up_ips:
                continue
            prev_status = h.status
            prev_missed = h.missed_scans
            h.missed_scans = (h.missed_scans or 0) + 1

            if h.missed_scans >= threshold:
                h.status = "offline"
                if prev_status != "offline":
                    record_change(
                        host_id=h.id,
                        change_type="host_offline",
                        severity="medium",
                        previous_value={"status": prev_status, "missed_scans": prev_missed},
                        current_value={"status": "offline", "missed_scans": h.missed_scans},
                    )
            else:
                h.status = "unstable"

    db.commit()

    return {
        "accepted": True,
        "scan_run_id": str(payload.scan_run_id),
        "chunk_id": str(payload.chunk_id),
        "status": payload.status,
        "hosts_processed": len(up_hosts),
        "changes_recorded": changes_recorded,
    }
