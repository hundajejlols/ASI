from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import String, cast, desc, func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.crypto import (
    AAD_HTTP_COOKIES,
    AAD_HTTP_HEADERS,
    AAD_OVERRIDE_NOTES,
    decrypt_field_safe,
    decrypt_json,
)
from app.core.security import Principal, require_permission
from app.db.models import AssetOverride, Host, HTTPFingerprint, Service, SignatureMatch
from app.db.session import get_db
from app.schemas.api import (
    HostDetailOut,
    HostSummaryOut,
    HTTPFingerprintOut,
    OverrideOut,
    ServiceOut,
    SignatureMatchOut,
)
from app.services.queries import fetch_latest_http_fingerprints

router = APIRouter(prefix="/hosts", tags=["hosts"])


def _serialize_override(ov: AssetOverride | None) -> OverrideOut | None:
    if ov is None:
        return None
    notes = (
        decrypt_field_safe(
            ov.notes_encrypted,
            default="[nie można odszyfrować notatki — niezgodny ENCRYPTION_MASTER_KEY]",
            associated_data=AAD_OVERRIDE_NOTES,
        )
        if ov.notes_encrypted
        else None
    )
    return OverrideOut(
        id=ov.id,
        entity_type=ov.entity_type,
        entity_id=ov.entity_id,
        custom_label=ov.custom_label,
        owner_unit=ov.owner_unit,
        criticality=ov.criticality,
        tags=list(ov.tags or []),
        is_false_positive=ov.is_false_positive,
        is_ignored=ov.is_ignored,
        notes=notes,
        updated_at=ov.updated_at,
    )


def _serialize_http_fp(fp: HTTPFingerprint | None) -> HTTPFingerprintOut | None:
    if fp is None:
        return None
    headers = decrypt_json(fp.headers_encrypted, default={}, associated_data=AAD_HTTP_HEADERS)
    cookies = decrypt_json(fp.cookies_encrypted, default=[], associated_data=AAD_HTTP_COOKIES)
    return HTTPFingerprintOut(
        id=fp.id,
        url=fp.url,
        scheme=fp.scheme,
        status_code=fp.status_code,
        response_time_ms=fp.response_time_ms,
        probe_error=fp.probe_error,
        title=fp.title,
        redirect_chain=list(fp.redirect_chain or []),
        headers=headers,
        cookies=cookies,
        favicon_mmh3_hash=fp.favicon_mmh3_hash,
        tls_subject=fp.tls_subject,
        tls_issuer=fp.tls_issuer,
        tls_not_after=fp.tls_not_after,
        tls_san=list(fp.tls_san or []),
        tls_is_self_signed=bool(fp.tls_subject and fp.tls_issuer and fp.tls_subject == fp.tls_issuer),
        technologies=list(fp.technologies or []),
        tech_confidence=dict(fp.tech_confidence or {}),
        is_admin_panel=fp.is_admin_panel,
        is_staging_env=fp.is_staging_env,
        captured_at=fp.captured_at,
    )


@router.get("", response_model=list[HostSummaryOut])
def list_hosts(
    response: Response,
    host_status: Literal["online", "unstable", "offline", "archived"] | None = Query(default=None, alias="status"),
    search: str | None = Query(default=None, description="Filtrowanie serwerowe po IP, hostname, etykiecie lub jednostce"),
    include_ignored: bool = Query(default=True),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("read")),
) -> list[HostSummaryOut]:
    base_filter = []
    if host_status:
        base_filter.append(Host.status == host_status)
    if search and search.strip():
        q = f"%{search.strip()}%"
        ov_host_ids = select(AssetOverride.entity_id).where(
            AssetOverride.entity_type == "host",
            or_(
                AssetOverride.custom_label.ilike(q),
                AssetOverride.owner_unit.ilike(q),
                cast(AssetOverride.tags, String).ilike(q),
            ),
        )
        base_filter.append(
            or_(
                cast(Host.ip_address, String).ilike(q),
                Host.hostname.ilike(q),
                Host.id.in_(ov_host_ids),
            )
        )

    total_count = int(
        db.execute(select(func.count(Host.id)).where(*base_filter)).scalar_one()
    )
    response.headers["X-Total-Count"] = str(total_count)

    stmt = (
        select(Host)
        .where(*base_filter)
        .options(
            selectinload(Host.services)
            .selectinload(Service.signature_matches)
            .selectinload(SignatureMatch.signature)
        )
        .order_by(desc(Host.last_seen_at))
        .limit(limit)
        .offset(offset)
    )
    hosts = db.execute(stmt).scalars().all()
    if not hosts:
        return []

    host_ids = [h.id for h in hosts]
    all_open_svc_ids = [
        s.id
        for h in hosts
        if h.status not in ("offline", "archived")
        for s in h.services
        if s.state == "open"
    ]
    # Jedno zapytanie SQL (DISTINCT ON) zamiast N+1
    latest_fp_map = fetch_latest_http_fingerprints(db, all_open_svc_ids)

    overrides_rows = db.execute(
        select(AssetOverride).where(
            AssetOverride.entity_type == "host",
            AssetOverride.entity_id.in_(host_ids),
        )
    ).scalars().all()
    overrides_map = {ov.entity_id: ov for ov in overrides_rows}

    sev_rank = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    rank_to_sev = {v: k for k, v in sev_rank.items()}

    results: list[HostSummaryOut] = []
    for h in hosts:
        ov = overrides_map.get(h.id)
        if not include_ignored and ov and ov.is_ignored:
            continue

        open_services = [s for s in h.services if s.state == "open"] if h.status not in ("offline", "archived") else []
        is_admin = False
        is_staging = False
        tech_set: set[str] = set()
        sig_ids: set[UUID] = set()
        max_sev_rank = 1

        if ov and ov.criticality:
            max_sev_rank = max(max_sev_rank, sev_rank.get(ov.criticality, 1))

        for svc in open_services:
            latest_fp = latest_fp_map.get(svc.id)
            if latest_fp:
                if latest_fp.is_admin_panel:
                    is_admin = True
                    max_sev_rank = max(max_sev_rank, sev_rank["medium"])
                if latest_fp.is_staging_env:
                    is_staging = True
                    max_sev_rank = max(max_sev_rank, sev_rank["low"])
                for t in latest_fp.technologies or []:
                    if t:
                        tech_set.add(str(t))

            for m in svc.signature_matches:
                if m.signature and m.signature.is_enabled:
                    sig_ids.add(m.signature_id)
                    max_sev_rank = max(max_sev_rank, sev_rank.get(m.signature.severity, 1))

        score = min(
            100,
            (35 if is_admin else 0)
            + (25 if is_staging else 0)
            + min(30, len(sig_ids) * 6)
            + (max_sev_rank - 1) * 5,
        )

        results.append(
            HostSummaryOut(
                id=h.id,
                ip_address=str(h.ip_address),
                hostname=h.hostname,
                status=h.status,
                missed_scans=h.missed_scans,
                open_services_count=len(open_services),
                is_admin_panel=is_admin,
                is_staging_env=is_staging,
                technologies=sorted(tech_set),
                signature_matches_count=len(sig_ids),
                highest_severity=rank_to_sev.get(max_sev_rank, "info"),
                priority_score=score,
                first_seen_at=h.first_seen_at,
                last_seen_at=h.last_seen_at,
                override=_serialize_override(ov),
            )
        )
    return results


@router.get("/{host_id}", response_model=HostDetailOut)
def get_host_detail(
    host_id: UUID,
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("read")),
) -> HostDetailOut:
    host = db.execute(
        select(Host)
        .where(Host.id == host_id)
        .options(
            selectinload(Host.services).selectinload(Service.signature_matches).selectinload(SignatureMatch.signature),
        )
    ).scalar_one_or_none()

    if host is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Nie znaleziono hosta o podanym ID.",
        )

    host_override = db.execute(
        select(AssetOverride).where(
            AssetOverride.entity_type == "host",
            AssetOverride.entity_id == host.id,
        )
    ).scalar_one_or_none()

    service_ids = [s.id for s in host.services]
    latest_fp_map = fetch_latest_http_fingerprints(db, service_ids)

    svc_overrides_map: dict[UUID, AssetOverride] = {}
    if service_ids:
        svc_overrides = db.execute(
            select(AssetOverride).where(
                AssetOverride.entity_type == "service",
                AssetOverride.entity_id.in_(service_ids),
            )
        ).scalars().all()
        svc_overrides_map = {ov.entity_id: ov for ov in svc_overrides}

    services_out: list[ServiceOut] = []
    for svc in sorted(host.services, key=lambda s: (s.port, s.protocol)):
        latest_fp = latest_fp_map.get(svc.id)

        seen_sig_ids: set[UUID] = set()
        sig_matches_out: list[SignatureMatchOut] = []
        for m in sorted(svc.signature_matches, key=lambda x: x.matched_at, reverse=True):
            if m.signature_id in seen_sig_ids:
                continue
            if m.signature is not None and not m.signature.is_enabled:
                continue
            seen_sig_ids.add(m.signature_id)
            sig_matches_out.append(
                SignatureMatchOut(
                    id=m.id,
                    signature_id=m.signature_id,
                    signature_name=m.signature.name if m.signature else "unknown",
                    severity=m.signature.severity if m.signature else "info",
                    matched_evidence=m.matched_evidence,
                    matched_at=m.matched_at,
                )
            )

        effective_state = "unreachable" if (host.status == "offline" and svc.state == "open") else svc.state
        services_out.append(
            ServiceOut(
                id=svc.id,
                port=svc.port,
                protocol=svc.protocol,
                state=effective_state,
                service_name=svc.service_name,
                product=svc.product,
                version=svc.version,
                banner=svc.banner,
                missed_scans=svc.missed_scans,
                first_seen_at=svc.first_seen_at,
                last_seen_at=svc.last_seen_at,
                latest_http_fingerprint=_serialize_http_fp(latest_fp),
                signature_matches=sig_matches_out,
                override=_serialize_override(svc_overrides_map.get(svc.id)),
            )
        )

    return HostDetailOut(
        id=host.id,
        ip_address=str(host.ip_address),
        hostname=host.hostname,
        status=host.status,
        missed_scans=host.missed_scans,
        first_seen_at=host.first_seen_at,
        last_seen_at=host.last_seen_at,
        last_scan_run_id=host.last_scan_run_id,
        override=_serialize_override(host_override),
        services=services_out,
    )
