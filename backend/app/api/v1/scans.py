import csv
import io
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

import redis
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.core.crypto import (
    AAD_HTTP_COOKIES,
    AAD_HTTP_HEADERS,
    AAD_OVERRIDE_NOTES,
    decrypt_field_safe,
    decrypt_json,
)
from app.core.security import Principal, require_permission, verify_scanner_token
from app.db.models import (
    AssetOverride,
    ChangeEvent,
    CustomSignature,
    Host,
    HTTPFingerprint,
    ScanChunk,
    ScanProfile,
    ScanRun,
    Service,
    SignatureMatch,
    TargetGroup,
)
from app.db.session import get_db
from app.schemas.contract import (
    HostResult,
    HTTPFingerprintResult,
    ScanChunkResult,
    ScanJobChunk,
    ScanProfilePayload,
    ServiceResult,
    SignatureMatchResult,
)
from app.services.audit import record_audit_event
from app.services.chunker import (
    cancel_scan_run,
    detect_target_type,
    load_active_signatures,
    reconcile_stale_scan_runs,
    reprobe_unstable_hosts,
    resume_scan_run,
    start_scan_run,
    validate_nmap_flags,
    validate_ports_spec,
)
from app.services.ingest import ingest_scan_result
from app.services.queries import fetch_latest_http_fingerprints
from app.services.scope import resolve_principal_scope
from app.services.seed import ensure_default_group_and_profile

router = APIRouter(prefix="/scans", tags=["scans"])


class ScanStartRequest(BaseModel):
    target_group_id: UUID | None = None
    raw_targets: list[str] | None = Field(
        default=None,
        description="Opcjonalna lista celów (IP/CIDR/domena); jeśli pusta, używa aktywnych celów z grupy.",
    )
    profile_id: UUID | None = None
    ports: str | None = Field(
        default=None,
        description="Opcjonalna lista/zakres portów nmap (np. '80,443,8080,8443,22', '1-1024' lub 'top-1000').",
    )
    chunk_cidr_prefix: int | None = Field(default=None, ge=16, le=32)
    adaptive_chunking: bool = Field(
        default=False,
        description="Gdy true, automatycznie dobiera maskę CIDR (/24../28) na podstawie zmierzonej prędkości skanowania i długości okna.",
    )
    rate_limit_pps: int | None = Field(default=None, ge=1)
    window_minutes: int = Field(default=60, ge=1, le=1440)
    dry_run: bool = False


class ScanResumeRequest(BaseModel):
    window_minutes: int = Field(default=60, ge=1, le=1440)
    rate_limit_pps: int | None = Field(default=None, ge=1)
    ports: str | None = Field(default=None)


class ScanProfileUpdateRequest(BaseModel):
    nmap_flags: str | None = None
    ports: str | None = None
    rate_limit_pps: int | None = Field(default=None, ge=1, le=10000)
    max_concurrency: int | None = Field(default=None, ge=1, le=64)
    chunk_cidr_prefix: int | None = Field(default=None, ge=16, le=32)
    http_fingerprint_enabled: bool | None = None
    signatures_enabled: bool | None = None


class ManualFindingRequest(BaseModel):
    ip_address: str
    hostname: str | None = None
    port: int = Field(..., ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    http_url: str | None = None
    http_status: int | None = Field(default=None, ge=100, le=599)
    http_title: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: list[str] = Field(default_factory=list)
    favicon_mmh3_hash: str | None = None
    technologies: list[str] = Field(default_factory=list)
    is_admin_panel: bool = False
    is_staging_env: bool = False


@router.post("/start")
def start_scan(
    payload: ScanStartRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("add")),
) -> dict[str, Any]:
    """
    Uruchamia skan: scala nakładające się zakresy CIDR, dzieli na paczki (statycznie lub adaptacyjnie wg szybkości skanowania),
    tworzy scan_runs i scan_chunks oraz wrzuca paczki na Redis z window_deadline_utc i aktywnymi sygnaturami.
    """
    scope = resolve_principal_scope(db, principal)
    try:
        res = start_scan_run(
            db,
            target_group_id=payload.target_group_id,
            raw_targets=payload.raw_targets,
            profile_id=payload.profile_id,
            chunk_prefix_override=payload.chunk_cidr_prefix,
            adaptive_chunking=payload.adaptive_chunking,
            rate_limit_pps=payload.rate_limit_pps,
            ports_override=payload.ports,
            window_minutes=payload.window_minutes,
            dry_run=payload.dry_run,
            scope=scope,
        )
        if not payload.dry_run:
            record_audit_event(
                db,
                principal,
                action="scan.start",
                resource_type="scan_run",
                resource_id=str(res.get("scan_run_id")),
                details={"chunks": res.get("total_chunks"), "ports": res.get("ports"), "adaptive": payload.adaptive_chunking},
            )
            db.commit()
        return res
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@router.get("/profiles")
def list_scan_profiles(
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("read")),
) -> list[dict[str, Any]]:
    rows = db.execute(select(ScanProfile).order_by(ScanProfile.name)).scalars().all()
    return [
        {
            "id": str(p.id),
            "name": p.name,
            "nmap_flags": p.nmap_flags,
            "ports": p.ports,
            "rate_limit_pps": p.rate_limit_pps,
            "max_concurrency": p.max_concurrency,
            "chunk_cidr_prefix": p.chunk_cidr_prefix,
            "http_fingerprint_enabled": p.http_fingerprint_enabled,
            "signatures_enabled": p.signatures_enabled,
        }
        for p in rows
    ]


@router.patch("/profiles/{profile_id}")
def update_scan_profile(
    profile_id: UUID,
    payload: ScanProfileUpdateRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("modify")),
) -> dict[str, Any]:
    """Edycja konfiguracji profilu skanowania z twardą białą listą flag nmap."""
    prof = db.get(ScanProfile, profile_id)
    if prof is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono profilu skanowania.")

    fields = payload.model_fields_set
    try:
        if "nmap_flags" in fields and payload.nmap_flags is not None:
            prof.nmap_flags = validate_nmap_flags(payload.nmap_flags)
        if "ports" in fields and payload.ports is not None:
            prof.ports = validate_ports_spec(payload.ports)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    for f in ("rate_limit_pps", "max_concurrency", "chunk_cidr_prefix", "http_fingerprint_enabled", "signatures_enabled"):
        if f in fields and getattr(payload, f) is not None:
            setattr(prof, f, getattr(payload, f))

    record_audit_event(db, principal, action="scan_profile.update", resource_type="scan_profile", resource_id=str(prof.id), details={"fields": sorted(fields)})
    db.commit()
    db.refresh(prof)
    return {
        "id": str(prof.id),
        "name": prof.name,
        "nmap_flags": prof.nmap_flags,
        "ports": prof.ports,
        "rate_limit_pps": prof.rate_limit_pps,
        "max_concurrency": prof.max_concurrency,
        "chunk_cidr_prefix": prof.chunk_cidr_prefix,
        "http_fingerprint_enabled": prof.http_fingerprint_enabled,
        "signatures_enabled": prof.signatures_enabled,
    }


def _serialize_scan_run(scan_run: ScanRun) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    duration_sec: float | None = None
    if scan_run.started_at:
        end_ts = (
            scan_run.finished_at
            or scan_run.paused_at
            or (now if scan_run.status == "running" else None)
        )
        if end_ts:
            duration_sec = round(max(0.0, (end_ts - scan_run.started_at).total_seconds()), 2)
    return {
        "id": str(scan_run.id),
        "status": scan_run.status,
        "total_chunks": scan_run.total_chunks,
        "completed_chunks": scan_run.completed_chunks,
        "duration_seconds": duration_sec,
        "window_deadline_at": scan_run.window_deadline_at.isoformat() if scan_run.window_deadline_at else None,
        "started_at": scan_run.started_at.isoformat() if scan_run.started_at else None,
        "paused_at": scan_run.paused_at.isoformat() if scan_run.paused_at else None,
        "finished_at": scan_run.finished_at.isoformat() if scan_run.finished_at else None,
        "created_at": scan_run.created_at.isoformat() if scan_run.created_at else None,
    }


@router.get("/runs")
def list_scan_runs(
    limit: int = Query(default=10, ge=1, le=50),
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("read")),
) -> list[dict[str, Any]]:
    """Zwraca listę ostatnich przebiegów skanów wraz z czasem trwania i postępem paczek (z auto-reconcile wygasłych)."""
    reconcile_stale_scan_runs(db)
    runs = db.execute(
        select(ScanRun).order_by(desc(ScanRun.created_at)).limit(limit)
    ).scalars().all()
    return [_serialize_scan_run(r) for r in runs]


@router.get("/runs/{scan_run_id}")
def get_scan_run_status(
    scan_run_id: UUID,
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("read")),
) -> dict[str, Any]:
    """Zwraca aktualny status przebiegu skanu, czas trwania (duration_seconds) i postęp jego paczek."""
    scan_run = db.get(ScanRun, scan_run_id)
    if scan_run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono scan_run.")
    return _serialize_scan_run(scan_run)


@router.get("/compare")
def compare_two_scan_runs(
    run_a: UUID = Query(..., description="ID wcześniejszego/bazowego przebiegu skanu"),
    run_b: UUID = Query(..., description="ID drugiego/porównywanego przebiegu skanu"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("read")),
) -> dict[str, Any]:
    """
    Porównuje dwa dowolne przebiegi skanów (Run A vs Run B):
    - różnice wykrytych endpointów HTTP/HTTPS (nowe, zniknięte, zmienione status_code/title/technologies/TLS/admin/staging),
    - wszystkie zdarzenia Diff (change_events) zarejestrowane pomiędzy czasem Run A a Run B.
    """
    scope = resolve_principal_scope(db, principal)
    scope_flt = scope.sql_host_filter()

    sr_a = db.get(ScanRun, run_a)
    sr_b = db.get(ScanRun, run_b)
    if sr_a is None or sr_b is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono jednego lub obu przebiegów skanu.")

    def _snapshot_for_run(run_id: UUID) -> dict[str, dict[str, Any]]:
        snap_stmt = (
            select(HTTPFingerprint, Service, Host)
            .join(Service, Service.id == HTTPFingerprint.service_id)
            .join(Host, Host.id == Service.host_id)
            .where(HTTPFingerprint.scan_run_id == run_id)
        )
        if scope_flt is not None:
            snap_stmt = snap_stmt.where(scope_flt)
        rows = db.execute(snap_stmt).all()
        snap: dict[str, dict[str, Any]] = {}
        for fp, svc, host in rows:
            ip_str = str(host.ip_address).split("/")[0]
            key = f"{ip_str}:{svc.port}/{svc.protocol}"
            snap[key] = {
                "host_ip": ip_str,
                "hostname": host.hostname,
                "port": svc.port,
                "protocol": svc.protocol,
                "url": fp.url,
                "status_code": fp.status_code,
                "title": fp.title,
                "technologies": sorted(set(fp.technologies or [])),
                "favicon_mmh3_hash": fp.favicon_mmh3_hash,
                "tls_subject": fp.tls_subject,
                "tls_not_after": fp.tls_not_after.isoformat() if fp.tls_not_after else None,
                "is_admin_panel": fp.is_admin_panel,
                "is_staging_env": fp.is_staging_env,
            }
        return snap

    snap_a = _snapshot_for_run(run_a)
    snap_b = _snapshot_for_run(run_b)

    keys_a = set(snap_a.keys())
    keys_b = set(snap_b.keys())

    added_endpoints = [snap_b[k] for k in sorted(keys_b - keys_a)]
    removed_endpoints = [snap_a[k] for k in sorted(keys_a - keys_b)]
    changed_endpoints: list[dict[str, Any]] = []
    unchanged_count = 0

    compare_fields = (
        "status_code",
        "title",
        "technologies",
        "favicon_mmh3_hash",
        "tls_subject",
        "tls_not_after",
        "is_admin_panel",
        "is_staging_env",
    )
    for k in sorted(keys_a & keys_b):
        diffs: dict[str, dict[str, Any]] = {}
        for f in compare_fields:
            if snap_a[k].get(f) != snap_b[k].get(f):
                diffs[f] = {"run_a": snap_a[k].get(f), "run_b": snap_b[k].get(f)}
        if diffs:
            changed_endpoints.append({"endpoint": k, "diffs": diffs})
        else:
            unchanged_count += 1

    # Zdarzenia change_events między oknem czasowym run_a i run_b
    t_start = min(sr_a.created_at, sr_b.created_at)
    t_end = max(sr_a.finished_at or sr_a.created_at, sr_b.finished_at or sr_b.created_at)
    events_stmt = (
        select(ChangeEvent)
        .options(selectinload(ChangeEvent.host), selectinload(ChangeEvent.service))
        .where(ChangeEvent.detected_at >= t_start, ChangeEvent.detected_at <= t_end)
        .order_by(desc(ChangeEvent.detected_at))
        .limit(200)
    )
    if scope_flt is not None:
        events_stmt = events_stmt.join(Host, Host.id == ChangeEvent.host_id).where(scope_flt)
    events_between = db.execute(events_stmt).scalars().all()

    return {
        "run_a": _serialize_scan_run(sr_a),
        "run_b": _serialize_scan_run(sr_b),
        "summary": {
            "run_a_endpoints": len(snap_a),
            "run_b_endpoints": len(snap_b),
            "added": len(added_endpoints),
            "removed": len(removed_endpoints),
            "changed": len(changed_endpoints),
            "unchanged": unchanged_count,
            "change_events_between": len(events_between),
        },
        "added_endpoints": added_endpoints,
        "removed_endpoints": removed_endpoints,
        "changed_endpoints": changed_endpoints,
        "events_between": [
            {
                "id": str(ev.id),
                "change_type": ev.change_type,
                "severity": ev.severity,
                "host_ip": str(ev.host.ip_address).split("/")[0] if ev.host else None,
                "service_port": ev.service.port if ev.service else None,
                "previous_value": ev.previous_value,
                "current_value": ev.current_value,
                "detected_at": ev.detected_at.isoformat(),
            }
            for ev in events_between
        ],
    }


@router.post("/{scan_run_id}/resume")
def resume_scan(
    scan_run_id: UUID,
    payload: ScanResumeRequest = ScanResumeRequest(),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("add")),
) -> dict[str, Any]:
    """
    Wznawia skan po przekroczeniu okna czasowego — kolejkuje w Redis wyłącznie
    niedokończone paczki (requeued_window / pending) z nowym window_deadline_utc.
    """
    try:
        res = resume_scan_run(
            db,
            scan_run_id=scan_run_id,
            window_minutes=payload.window_minutes,
            rate_limit_pps=payload.rate_limit_pps,
            ports_override=payload.ports,
        )
        record_audit_event(db, principal, action="scan.resume", resource_type="scan_run", resource_id=str(scan_run_id), details={"requeued_chunks": res.get("requeued_chunks")})
        db.commit()
        return res
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@router.post("/{scan_run_id}/cancel")
def cancel_scan(
    scan_run_id: UUID,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("add")),
) -> dict[str, Any]:
    """Anuluje aktywny lub zapauzowany przebieg skanu."""
    try:
        res = cancel_scan_run(db, scan_run_id=scan_run_id)
        record_audit_event(db, principal, action="scan.cancel", resource_type="scan_run", resource_id=str(scan_run_id), details={"cancelled_chunks": res.get("cancelled_chunks")})
        db.commit()
        return res
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.post("/reprobe-unstable")
def trigger_reprobe_unstable(
    window_minutes: int = Query(default=15, ge=1, le=240),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("add")),
) -> dict[str, Any]:
    """Uruchamia powtórny pomiar wyłącznie dla hostów oznaczonych jako 'unstable'."""
    scope = resolve_principal_scope(db, principal)
    try:
        res = reprobe_unstable_hosts(db, window_minutes=window_minutes, scope=scope)
        if res.get("queued"):
            record_audit_event(db, principal, action="scan.reprobe_unstable", resource_type="scan_run", resource_id=str(res.get("scan_run_id")), details={"unstable_hosts_count": res.get("unstable_hosts_count")})
            db.commit()
        return res
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@router.post("/enqueue-lab-demo")
def enqueue_lab_demo(
    target_cidr: str = "172.28.0.10/31",
    window_minutes: int = 30,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("add")),
) -> dict:
    """
    Demo endpoint: tworzy rekordy scan_runs i scan_chunks w PostgreSQL
    oraz wrzuca paczkę testową na kolejkę Redis (lab_net) z aktywnymi sygnaturami.
    """
    scope = resolve_principal_scope(db, principal)
    try:
        target_cidr, target_type = detect_target_type(target_cidr)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    scope.assert_targets_allowed([(target_cidr, target_type)])

    group, profile = ensure_default_group_and_profile(db)

    deadline = datetime.now(timezone.utc) + timedelta(minutes=window_minutes)
    scan_run_id = uuid4()
    chunk_id = uuid4()

    scan_run = ScanRun(
        id=scan_run_id,
        target_group_id=group.id,
        profile_id=profile.id,
        status="queued",
        window_deadline_at=deadline,
        total_chunks=1,
        completed_chunks=0,
    )
    chunk = ScanChunk(
        id=chunk_id,
        scan_run_id=scan_run_id,
        target_cidr=target_cidr,
        status="pending",
    )
    db.add(scan_run)
    db.add(chunk)
    db.commit()

    active_signatures = load_active_signatures(db) if profile.signatures_enabled else []

    job = ScanJobChunk(
        scan_run_id=scan_run_id,
        chunk_id=chunk_id,
        target_cidr=target_cidr,
        window_deadline_utc=deadline,
        profile=ScanProfilePayload(
            nmap_flags=profile.nmap_flags,
            ports=profile.ports,
            rate_limit_pps=profile.rate_limit_pps,
            http_fingerprint_enabled=profile.http_fingerprint_enabled,
            signatures_enabled=profile.signatures_enabled,
        ),
        signatures=active_signatures,
    )
    try:
        client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=3)
        client.rpush(settings.redis_job_queue, job.model_dump_json())
    except redis.RedisError as exc:
        scan_run.status = "failed"
        scan_run.finished_at = datetime.now(timezone.utc)
        chunk.status = "failed"
        chunk.error_message = f"Redis unavailable: {exc}"
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Kolejka Redis jest niedostępna: {exc}",
        ) from exc

    return {
        "queued": True,
        "queue": settings.redis_job_queue,
        "scan_run_id": str(scan_run_id),
        "chunk_id": str(chunk_id),
        "target_cidr": target_cidr,
        "active_signatures_count": len(active_signatures),
    }


@router.post("/ingest", dependencies=[Depends(verify_scanner_token)])
def ingest_scan_chunk(
    payload: ScanChunkResult,
    db: Session = Depends(get_db),
) -> dict:
    """
    Odbiera wyniki paczki ze skanera i przekazuje do wspólnego serwisu ingest_scan_result.
    """
    return ingest_scan_result(db=db, payload=payload, is_partial=False)


@router.post("/manual", status_code=status.HTTP_201_CREATED)
def submit_manual_finding(
    payload: ManualFindingRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("add")),
) -> dict[str, Any]:
    """
    Ręczne wprowadzenie obserwacji hosta/usługi przez formularz UI/API.
    Przechodzi przez ten sam pipeline ingest_scan_result (Diff, AES-256-GCM + AAD, pasywne sygnatury, ochrona asset_overrides).
    """
    raw_ip = payload.ip_address.strip().split("/")[0]
    try:
        ip_str = str(ipaddress.ip_address(raw_ip))
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Nieprawidłowy adres IP: {payload.ip_address!r}",
        ) from exc

    scope = resolve_principal_scope(db, principal)
    scope.assert_ip_allowed(ip_str)

    now = datetime.now(timezone.utc)
    http_fp: HTTPFingerprintResult | None = None
    has_http_meta = bool(
        payload.http_url
        or payload.http_title
        or payload.http_status is not None
        or payload.headers
        or payload.cookies
        or payload.favicon_mmh3_hash
        or payload.technologies
        or payload.is_admin_panel
        or payload.is_staging_env
    )
    if has_http_meta:
        default_scheme: Literal["http", "https"] = "https" if payload.port in (443, 8443, 9443) else "http"
        url_str = (payload.http_url or f"{default_scheme}://{ip_str}:{payload.port}/").strip()
        scheme: Literal["http", "https"] = "https" if url_str.lower().startswith("https://") else "http"
        http_fp = HTTPFingerprintResult(
            url=url_str,
            scheme=scheme,
            status_code=payload.http_status or 200,
            title=payload.http_title.strip() if payload.http_title else None,
            headers=payload.headers,
            cookies=[c.strip() for c in payload.cookies if c.strip()],
            favicon_mmh3_hash=payload.favicon_mmh3_hash.strip() if payload.favicon_mmh3_hash else None,
            technologies=[t.strip() for t in payload.technologies if t.strip()],
            is_admin_panel=payload.is_admin_panel,
            is_staging_env=payload.is_staging_env,
        )

    scan_result = ScanChunkResult(
        scan_run_id=uuid4(),
        chunk_id=uuid4(),
        worker_id="manual-form",
        status="completed",
        started_at=now,
        finished_at=now,
        hosts=[
            HostResult(
                ip=ip_str,
                hostname=payload.hostname.strip() if payload.hostname else None,
                is_up=True,
                services=[
                    ServiceResult(
                        port=payload.port,
                        protocol=payload.protocol,
                        state="open",
                        service_name=payload.service_name.strip() if payload.service_name else None,
                        product=payload.product.strip() if payload.product else None,
                        version=payload.version.strip() if payload.version else None,
                        banner=payload.banner.strip() if payload.banner else None,
                        http=http_fp,
                        signature_matches=[],
                    )
                ],
            )
        ],
    )
    res = ingest_scan_result(db=db, payload=scan_result, is_partial=True)
    record_audit_event(db, principal, action="scan.manual_entry", resource_type="host", resource_id=ip_str, details={"port": payload.port, "changes": res.get("changes_recorded")})
    db.commit()
    return res


def _parse_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if val is None:
        return False
    return str(val).strip().lower() in ("true", "1", "yes", "t")


def _normalize_service_state(raw_state: Any) -> Literal["open", "filtered", "closed"]:
    st = str(raw_state or "open").strip().lower()
    if st in ("filtered", "closed"):
        return st  # type: ignore[return-value]
    return "open"


def _safe_int(val: Any, default: int) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _normalize_imported_json_hosts(
    raw_hosts: list[Any],
    sig_by_name: dict[str, CustomSignature],
) -> list[dict[str, Any]]:
    """
    Normalizuje listę hostów zarówno z kontraktu ScanChunkResult (worker Go),
    jak i z pliku wyeksportowanego przez GET /api/v1/scans/export?format=json (asi_export.json)
    lub uproszczonego JSON-a zewnętrznego.
    """
    normalized_hosts: list[dict[str, Any]] = []
    for idx, h in enumerate(raw_hosts):
        if not isinstance(h, dict):
            continue
        ip_raw = h.get("ip") or h.get("ip_address")
        if not ip_raw:
            continue
        ip_clean = str(ip_raw).strip().split("/")[0]
        try:
            ip_valid = str(ipaddress.ip_address(ip_clean))
        except ValueError as exc:
            raise ValueError(f"Nieprawidłowy adres IP w rekordzie #{idx + 1}: {ip_raw!r}") from exc

        if "is_up" in h and h["is_up"] is not None:
            is_up = bool(h["is_up"])
        elif "status" in h or "host_status" in h:
            st = str(h.get("status") or h.get("host_status") or "online").lower()
            is_up = st != "offline"
        else:
            is_up = True

        norm_services: list[dict[str, Any]] = []
        for s in h.get("services", []) or []:
            if not isinstance(s, dict) or s.get("port") is None or s.get("port") == "":
                continue
            port_num = _safe_int(s.get("port"), -1)
            if not (1 <= port_num <= 65535):
                raise ValueError(f"Nieprawidłowy numer portu ({s.get('port')!r}) dla hosta {ip_valid}.")
            proto = "udp" if str(s.get("protocol", "tcp")).lower() == "udp" else "tcp"
            state = _normalize_service_state(s.get("state") or s.get("service_state"))

            http_obj = s.get("http")
            if isinstance(http_obj, dict):
                url = str(http_obj.get("url") or f"http://{ip_valid}:{port_num}/")
                scheme = http_obj.get("scheme") or ("https" if url.startswith("https://") else "http")
                http_dict: dict[str, Any] | None = {
                    **http_obj,
                    "url": url,
                    "scheme": "https" if scheme == "https" else "http",
                    "status_code": _safe_int(http_obj.get("status_code"), 200),
                }
            else:
                http_url = s.get("http_url") or s.get("url")
                has_http_fields = bool(
                    http_url
                    or s.get("http_status") is not None
                    or s.get("status_code") is not None
                    or s.get("http_title")
                    or s.get("title")
                    or s.get("headers")
                    or s.get("cookies")
                    or s.get("favicon_mmh3_hash")
                    or s.get("tls")
                    or s.get("technologies")
                    or _parse_bool(s.get("is_admin_panel"))
                    or _parse_bool(s.get("is_staging_env"))
                )
                if has_http_fields:
                    default_scheme = "https" if port_num in (443, 8443, 9443) else "http"
                    host_fmt = f"[{ip_valid}]" if ":" in ip_valid else ip_valid
                    url_str = str(http_url or f"{default_scheme}://{host_fmt}:{port_num}/")
                    status_code = _safe_int(s.get("http_status") or s.get("status_code"), 200)
                    http_dict = {
                        "url": url_str,
                        "scheme": "https" if url_str.startswith("https://") else "http",
                        "status_code": status_code,
                        "title": s.get("http_title") or s.get("title"),
                        "redirect_chain": list(s.get("redirect_chain") or []),
                        "headers": dict(s.get("headers") or {}) if isinstance(s.get("headers"), dict) else {},
                        "cookies": list(s.get("cookies") or []),
                        "favicon_mmh3_hash": s.get("favicon_mmh3_hash"),
                        "tls": s.get("tls") if isinstance(s.get("tls"), dict) else None,
                        "technologies": list(s.get("technologies") or []),
                        "is_admin_panel": _parse_bool(s.get("is_admin_panel")),
                        "is_staging_env": _parse_bool(s.get("is_staging_env")),
                    }
                else:
                    http_dict = None

            sig_matches: list[dict[str, Any]] = []
            for raw_sig in s.get("signature_matches", []) or []:
                if isinstance(raw_sig, dict):
                    sig_id = raw_sig.get("signature_id")
                    sig_name = raw_sig.get("signature_name") or raw_sig.get("name") or ""
                    if not sig_id and sig_name and sig_name.lower() in sig_by_name:
                        sig_id = str(sig_by_name[sig_name.lower()].id)
                    if sig_id:
                        sig_matches.append(
                            {
                                "signature_id": sig_id,
                                "signature_name": sig_name or "imported",
                                "evidence": str(raw_sig.get("evidence") or raw_sig.get("matched_evidence") or "imported"),
                            }
                        )
                elif isinstance(raw_sig, str) and raw_sig.strip():
                    matched_sig = sig_by_name.get(raw_sig.strip().lower())
                    if matched_sig is not None:
                        sig_matches.append(
                            {
                                "signature_id": str(matched_sig.id),
                                "signature_name": matched_sig.name,
                                "evidence": "imported",
                            }
                        )

            norm_services.append(
                {
                    "port": port_num,
                    "protocol": proto,
                    "state": state,
                    "service_name": s.get("service_name"),
                    "product": s.get("product"),
                    "version": s.get("version"),
                    "banner": s.get("banner"),
                    "http": http_dict,
                    "signature_matches": sig_matches,
                }
            )

        normalized_hosts.append(
            {
                "ip": ip_valid,
                "hostname": h.get("hostname"),
                "is_up": is_up,
                "services": norm_services,
            }
        )
    return normalized_hosts


@router.post("/import")
async def import_scan_results(
    file: UploadFile = File(...),
    target_cidr: str | None = Query(default=None),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("add")),
) -> dict[str, Any]:
    """
    Import wyników z pliku JSON lub CSV przez ten sam pipeline ingest_scan_result
    (pełny Diff, szyfrowanie AES-256-GCM + AAD nagłówków/ciasteczek i ochrona asset_overrides).
    Zawsze działa w bezpiecznym trybie partial (nie zamyka nieobecnych usług na istniejących hostach).
    """
    raw_bytes = await file.read()
    content = raw_bytes.decode("utf-8-sig", errors="replace").strip()
    if not content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Przesłany plik wyników jest pusty.")
    filename = (file.filename or "").lower()
    now = datetime.now(timezone.utc)

    all_sigs = db.execute(select(CustomSignature)).scalars().all()
    sig_by_name = {s.name.lower(): s for s in all_sigs}

    if filename.endswith(".json") or content.startswith("{") or content.startswith("["):
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Błędny JSON: {exc}") from exc

        if isinstance(data, list):
            data = {"hosts": data}
        if not isinstance(data, dict):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Oczekiwano obiektu lub tablicy JSON.")

        effective_cidr = target_cidr or data.get("target_cidr")
        try:
            norm_hosts = _normalize_imported_json_hosts(data.get("hosts", []), sig_by_name)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

        if not norm_hosts:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Plik JSON nie zawiera żadnych poprawnych rekordów hostów (wymagane pole 'ip' lub 'ip_address').",
            )

        raw_worker = str(data.get("worker_id") or "").strip()
        import_worker_id = raw_worker if raw_worker.startswith("import-") else "import-json"
        normalized = {
            "schema_version": "1.0",
            "scan_run_id": str(uuid4()),
            "chunk_id": str(uuid4()),
            "worker_id": import_worker_id,
            "status": "completed",
            "error_message": data.get("error_message"),
            "started_at": data.get("started_at") or now.isoformat(),
            "finished_at": data.get("finished_at") or now.isoformat(),
            "hosts": norm_hosts,
        }
        try:
            scan_result = ScanChunkResult.model_validate(normalized)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Nieprawidłowy kontrakt JSON: {exc}") from exc

        scope = resolve_principal_scope(db, principal)
        if scope.restricted:
            scope.assert_targets_allowed([(h.ip, "ip") for h in scan_result.hosts])

        res = ingest_scan_result(db=db, payload=scan_result, target_cidr=effective_cidr, is_partial=True)
        record_audit_event(db, principal, action="scan.import_json", resource_type="scan_run", resource_id=str(res.get("scan_run_id")), details={"filename": file.filename, "hosts": res.get("hosts_processed")})
        db.commit()
        return res

    # Parser CSV -> ScanChunkResult (z autodetekcją separatora ',' / ';' / '\t')
    first_line = content.splitlines()[0] if content else ""
    delimiter = ","
    try:
        dialect = csv.Sniffer().sniff(content[:4096], delimiters=",;\t")
        delimiter = dialect.delimiter
    except csv.Error:
        if ";" in first_line and "," not in first_line:
            delimiter = ";"
        elif "\t" in first_line and "," not in first_line:
            delimiter = "\t"

    reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)
    if not reader.fieldnames:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Pusty lub nieprawidłowy plik CSV.")

    hosts_by_ip: dict[str, HostResult] = {}
    for row_idx, row in enumerate(reader, start=2):
        norm = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
        ip_raw = (norm.get("ip") or norm.get("ip_address") or "").split("/")[0].strip()
        if not ip_raw:
            continue
        try:
            ip = str(ipaddress.ip_address(ip_raw))
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Nieprawidłowy adres IP w wierszu CSV #{row_idx}: {ip_raw!r}",
            ) from exc

        host_status_raw = (norm.get("host_status") or norm.get("status") or "online").lower()
        is_up = host_status_raw != "offline"
        if ip not in hosts_by_ip:
            hosts_by_ip[ip] = HostResult(
                ip=ip,
                hostname=norm.get("hostname") or None,
                is_up=is_up,
                services=[],
            )
        port_raw = norm.get("port")
        if port_raw:
            port_num = _safe_int(port_raw, -1)
            if not (1 <= port_num <= 65535):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Nieprawidłowy numer portu ({port_raw!r}) w wierszu CSV #{row_idx} (dozwolone 1-65535).",
                )
            http_fp: HTTPFingerprintResult | None = None
            http_url = norm.get("http_url") or norm.get("url")
            tech_sep = "|" if (delimiter == ";" and "|" in (norm.get("technologies") or "")) else ";"
            techs = [t.strip() for t in (norm.get("technologies") or "").split(tech_sep) if t.strip()]
            is_admin_csv = _parse_bool(norm.get("is_admin_panel"))
            is_staging_csv = _parse_bool(norm.get("is_staging_env"))
            http_title_csv = norm.get("http_title") or norm.get("title") or None
            status_raw = norm.get("http_status") or norm.get("status_code") or ""
            fav_csv = norm.get("favicon_mmh3_hash") or None
            headers_csv: dict[str, str] = {}
            if norm.get("headers_json"):
                try:
                    parsed_hdr = json.loads(norm["headers_json"])
                    if isinstance(parsed_hdr, dict):
                        headers_csv = {str(k): str(v) for k, v in parsed_hdr.items()}
                except Exception:
                    pass
            cookies_sep = "|" if (delimiter == ";" and "|" in (norm.get("cookies") or "")) else ";"
            cookies_csv = [c.strip() for c in (norm.get("cookies") or "").split(cookies_sep) if c.strip()]

            if http_url or http_title_csv or status_raw or techs or is_admin_csv or is_staging_csv or headers_csv or cookies_csv or fav_csv:
                default_scheme: Literal["http", "https"] = "https" if port_num in (443, 8443, 9443) else "http"
                host_fmt = f"[{ip}]" if ":" in ip else ip
                final_url = http_url or f"{default_scheme}://{host_fmt}:{port_num}/"
                scheme: Literal["http", "https"] = "https" if final_url.startswith("https://") else "http"
                http_fp = HTTPFingerprintResult(
                    url=final_url,
                    scheme=scheme,
                    status_code=_safe_int(status_raw or "200", 200),
                    title=http_title_csv,
                    headers=headers_csv,
                    cookies=cookies_csv,
                    favicon_mmh3_hash=fav_csv,
                    technologies=techs,
                    is_admin_panel=is_admin_csv,
                    is_staging_env=is_staging_csv,
                )
            sig_matches_csv: list[SignatureMatchResult] = []
            sig_sep = "|" if (delimiter == ";" and "|" in (norm.get("signature_matches") or "")) else ";"
            for sname in (norm.get("signature_matches") or "").split(sig_sep):
                sname_clean = sname.strip().lower()
                if sname_clean and sname_clean in sig_by_name:
                    msig = sig_by_name[sname_clean]
                    sig_matches_csv.append(
                        SignatureMatchResult(
                            signature_id=msig.id,
                            signature_name=msig.name,
                            evidence="imported-csv",
                        )
                    )
            proto: Literal["tcp", "udp"] = "udp" if norm.get("protocol", "tcp").lower() == "udp" else "tcp"
            svc_state = _normalize_service_state(norm.get("service_state") or norm.get("state"))
            hosts_by_ip[ip].services.append(
                ServiceResult(
                    port=port_num,
                    protocol=proto,
                    state=svc_state,
                    service_name=norm.get("service_name") or None,
                    product=norm.get("product") or None,
                    version=norm.get("version") or None,
                    banner=norm.get("banner") or None,
                    http=http_fp,
                    signature_matches=sig_matches_csv,
                )
            )

    if not hosts_by_ip:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Plik CSV nie zawiera żadnych poprawnych rekordów hostów (wymagana kolumna 'ip' lub 'ip_address').",
        )

    scope = resolve_principal_scope(db, principal)
    if scope.restricted:
        scope.assert_targets_allowed([(ip_k, "ip") for ip_k in hosts_by_ip.keys()])

    scan_result = ScanChunkResult(
        scan_run_id=uuid4(),
        chunk_id=uuid4(),
        worker_id="import-csv",
        status="completed",
        started_at=now,
        finished_at=now,
        hosts=list(hosts_by_ip.values()),
    )
    res = ingest_scan_result(db=db, payload=scan_result, target_cidr=target_cidr, is_partial=True)
    record_audit_event(db, principal, action="scan.import_csv", resource_type="scan_run", resource_id=str(res.get("scan_run_id")), details={"filename": file.filename, "hosts": res.get("hosts_processed")})
    db.commit()
    return res


@router.get("/export")
def export_scan_state(
    format: Literal["json", "csv"] = Query(default="json"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("read")),
):
    """
    Eksport aktualnego stanu zasobów (hosty, usługi, technologie, dopasowane sygnatury oraz nadpisania).
    Zoptymalizowany zapytaniem batchowym DISTINCT ON (eliminacja N+1).
    """
    scope = resolve_principal_scope(db, principal)
    scope_flt = scope.sql_host_filter()

    export_stmt = (
        select(Host)
        .options(
            selectinload(Host.services)
            .selectinload(Service.signature_matches)
            .selectinload(SignatureMatch.signature)
        )
        .order_by(Host.ip_address)
    )
    if scope_flt is not None:
        export_stmt = export_stmt.where(scope_flt)
    hosts = db.execute(export_stmt).scalars().all()

    host_ids = [h.id for h in hosts]
    all_service_ids = [s.id for h in hosts for s in h.services]
    latest_fp_map = fetch_latest_http_fingerprints(db, all_service_ids)

    overrides_map: dict[UUID, AssetOverride] = {}
    if host_ids:
        ov_rows = db.execute(
            select(AssetOverride).where(
                AssetOverride.entity_type == "host",
                AssetOverride.entity_id.in_(host_ids),
            )
        ).scalars().all()
        overrides_map = {ov.entity_id: ov for ov in ov_rows}

    svc_overrides_map: dict[UUID, AssetOverride] = {}
    if all_service_ids:
        svc_ov_rows = db.execute(
            select(AssetOverride).where(
                AssetOverride.entity_type == "service",
                AssetOverride.entity_id.in_(all_service_ids),
            )
        ).scalars().all()
        svc_overrides_map = {ov.entity_id: ov for ov in svc_ov_rows}

    exported_hosts: list[dict[str, Any]] = []
    flat_rows: list[dict[str, Any]] = []

    def _ov_to_dict(ov: AssetOverride | None) -> dict[str, Any] | None:
        if ov is None:
            return None
        return {
            "custom_label": ov.custom_label,
            "owner_unit": ov.owner_unit,
            "criticality": ov.criticality,
            "tags": list(ov.tags or []),
            "is_false_positive": ov.is_false_positive,
            "is_ignored": ov.is_ignored,
            "notes": decrypt_field_safe(ov.notes_encrypted, associated_data=AAD_OVERRIDE_NOTES) if ov.notes_encrypted else None,
        }

    for h in hosts:
        ip_str = str(h.ip_address).split("/")[0]
        ov_data = _ov_to_dict(overrides_map.get(h.id))

        services_export: list[dict[str, Any]] = []
        for svc in sorted(h.services, key=lambda s: (s.port, s.protocol)):
            latest_fp = latest_fp_map.get(svc.id)
            svc_ov_data = _ov_to_dict(svc_overrides_map.get(svc.id))

            sig_names = sorted(
                {m.signature.name for m in svc.signature_matches if m.signature and m.signature.is_enabled}
            )
            techs = list(latest_fp.technologies or []) if latest_fp else []
            is_admin = bool(latest_fp and latest_fp.is_admin_panel)
            is_staging = bool(latest_fp and latest_fp.is_staging_env)

            dec_headers = decrypt_json(latest_fp.headers_encrypted, default={}, associated_data=AAD_HTTP_HEADERS) if latest_fp else {}
            dec_cookies = decrypt_json(latest_fp.cookies_encrypted, default=[], associated_data=AAD_HTTP_COOKIES) if latest_fp else []

            tls_export = None
            if latest_fp and latest_fp.tls_subject and latest_fp.tls_not_after:
                tls_export = {
                    "subject": latest_fp.tls_subject,
                    "issuer": latest_fp.tls_issuer or "",
                    "not_after": latest_fp.tls_not_after.isoformat(),
                    "san": list(latest_fp.tls_san or []),
                    "is_self_signed": bool(latest_fp.tls_subject == latest_fp.tls_issuer),
                }

            svc_dict = {
                "port": svc.port,
                "protocol": svc.protocol,
                "state": svc.state,
                "service_name": svc.service_name,
                "product": svc.product,
                "version": svc.version,
                "banner": svc.banner,
                "http_url": latest_fp.url if latest_fp else None,
                "http_status": latest_fp.status_code if latest_fp else None,
                "http_title": latest_fp.title if latest_fp else None,
                "redirect_chain": list(latest_fp.redirect_chain or []) if latest_fp else [],
                "headers": dec_headers,
                "cookies": dec_cookies,
                "tls": tls_export,
                "favicon_mmh3_hash": latest_fp.favicon_mmh3_hash if latest_fp else None,
                "is_admin_panel": is_admin,
                "is_staging_env": is_staging,
                "technologies": techs,
                "tech_confidence": dict(latest_fp.tech_confidence or {}) if latest_fp else {},
                "signature_matches": sig_names,
                "override": svc_ov_data,
            }
            services_export.append(svc_dict)
            flat_rows.append(
                {
                    "ip_address": ip_str,
                    "hostname": h.hostname or "",
                    "host_status": h.status,
                    "missed_scans": h.missed_scans,
                    "port": svc.port,
                    "protocol": svc.protocol,
                    "service_state": svc.state,
                    "service_name": svc.service_name or "",
                    "product": svc.product or "",
                    "version": svc.version or "",
                    "banner": svc.banner or "",
                    "http_url": latest_fp.url if latest_fp else "",
                    "http_status": latest_fp.status_code if latest_fp else "",
                    "http_title": latest_fp.title if latest_fp else "",
                    "favicon_mmh3_hash": latest_fp.favicon_mmh3_hash if latest_fp and latest_fp.favicon_mmh3_hash else "",
                    "cookies": ";".join(str(c) for c in dec_cookies),
                    "headers_json": json.dumps(dec_headers, ensure_ascii=False) if dec_headers else "",
                    "is_admin_panel": is_admin,
                    "is_staging_env": is_staging,
                    "technologies": ";".join(techs),
                    "signature_matches": ";".join(sig_names),
                    "override_label": ov_data["custom_label"] if ov_data and ov_data["custom_label"] else "",
                    "override_owner_unit": ov_data["owner_unit"] if ov_data and ov_data["owner_unit"] else "",
                    "override_criticality": ov_data["criticality"] if ov_data and ov_data["criticality"] else "",
                    "override_tags": ";".join(ov_data["tags"]) if ov_data else "",
                    "override_is_ignored": ov_data["is_ignored"] if ov_data else False,
                    "override_notes": ov_data["notes"] if ov_data and ov_data["notes"] else "",
                }
            )

        if not h.services:
            flat_rows.append(
                {
                    "ip_address": ip_str,
                    "hostname": h.hostname or "",
                    "host_status": h.status,
                    "missed_scans": h.missed_scans,
                    "port": "",
                    "protocol": "",
                    "service_state": "",
                    "service_name": "",
                    "product": "",
                    "version": "",
                    "banner": "",
                    "http_url": "",
                    "http_status": "",
                    "http_title": "",
                    "favicon_mmh3_hash": "",
                    "cookies": "",
                    "headers_json": "",
                    "is_admin_panel": False,
                    "is_staging_env": False,
                    "technologies": "",
                    "signature_matches": "",
                    "override_label": ov_data["custom_label"] if ov_data and ov_data["custom_label"] else "",
                    "override_owner_unit": ov_data["owner_unit"] if ov_data and ov_data["owner_unit"] else "",
                    "override_criticality": ov_data["criticality"] if ov_data and ov_data["criticality"] else "",
                    "override_tags": ";".join(ov_data["tags"]) if ov_data else "",
                    "override_is_ignored": ov_data["is_ignored"] if ov_data else False,
                    "override_notes": ov_data["notes"] if ov_data and ov_data["notes"] else "",
                }
            )

        exported_hosts.append(
            {
                "id": str(h.id),
                "ip_address": ip_str,
                "hostname": h.hostname,
                "status": h.status,
                "missed_scans": h.missed_scans,
                "first_seen_at": h.first_seen_at.isoformat(),
                "last_seen_at": h.last_seen_at.isoformat(),
                "override": ov_data,
                "services": services_export,
            }
        )

    if format == "json":
        return {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "total_hosts": len(exported_hosts),
            "hosts": exported_hosts,
        }

    fieldnames = [
        "ip_address",
        "hostname",
        "host_status",
        "missed_scans",
        "port",
        "protocol",
        "service_state",
        "service_name",
        "product",
        "version",
        "banner",
        "http_url",
        "http_status",
        "http_title",
        "favicon_mmh3_hash",
        "cookies",
        "headers_json",
        "is_admin_panel",
        "is_staging_env",
        "technologies",
        "signature_matches",
        "override_label",
        "override_owner_unit",
        "override_criticality",
        "override_tags",
        "override_is_ignored",
        "override_notes",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(flat_rows)
    buf.seek(0)

    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="asi_export.csv"'},
    )
