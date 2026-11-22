from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, selectinload

from app.core.security import Principal, require_permission
from app.db.models import ChangeEvent, Host
from app.db.session import get_db
from app.schemas.api import ChangeEventOut
from app.services.audit import record_audit_event
from app.services.scope import resolve_principal_scope

router = APIRouter(prefix="/changes", tags=["changes"])

ChangeTypeFilter = Literal[
    "host_new",
    "host_offline",
    "host_recovered",
    "service_new",
    "service_closed",
    "service_changed",
    "tls_changed",
    "tech_changed",
    "signature_matched",
]


class AcknowledgeRequest(BaseModel):
    acknowledged: bool = True


def _serialize_event(ev: ChangeEvent) -> ChangeEventOut:
    return ChangeEventOut(
        id=ev.id,
        scan_run_id=ev.scan_run_id,
        host_id=ev.host_id,
        host_ip=str(ev.host.ip_address) if ev.host else None,
        service_id=ev.service_id,
        service_port=ev.service.port if ev.service else None,
        service_protocol=ev.service.protocol if ev.service else None,
        change_type=ev.change_type,
        severity=ev.severity,
        previous_value=ev.previous_value,
        current_value=ev.current_value,
        acknowledged=ev.acknowledged,
        detected_at=ev.detected_at,
    )


@router.get("", response_model=list[ChangeEventOut])
def list_changes(
    scan_run_id: UUID | None = Query(default=None),
    change_type: ChangeTypeFilter | None = Query(default=None),
    acknowledged: bool | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("read")),
) -> list[ChangeEventOut]:
    scope = resolve_principal_scope(db, principal)
    scope_flt = scope.sql_host_filter()

    stmt = (
        select(ChangeEvent)
        .options(selectinload(ChangeEvent.host), selectinload(ChangeEvent.service))
        .order_by(desc(ChangeEvent.detected_at))
        .limit(limit)
        .offset(offset)
    )
    if scope_flt is not None:
        stmt = stmt.join(Host, Host.id == ChangeEvent.host_id).where(scope_flt)
    if scan_run_id is not None:
        stmt = stmt.where(ChangeEvent.scan_run_id == scan_run_id)
    if change_type is not None:
        stmt = stmt.where(ChangeEvent.change_type == change_type)
    if acknowledged is not None:
        stmt = stmt.where(ChangeEvent.acknowledged.is_(acknowledged))

    events = db.execute(stmt).scalars().all()
    return [_serialize_event(ev) for ev in events]


@router.patch("/{event_id}/acknowledge", response_model=ChangeEventOut)
def acknowledge_change(
    event_id: UUID,
    payload: AcknowledgeRequest = AcknowledgeRequest(),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("modify")),
) -> ChangeEventOut:
    """Oznacza zdarzenie Diff jako przeanalizowane/potwierdzone (dla ról od modify_read wzwyż)."""
    ev = db.execute(
        select(ChangeEvent)
        .where(ChangeEvent.id == event_id)
        .options(selectinload(ChangeEvent.host), selectinload(ChangeEvent.service))
    ).scalar_one_or_none()
    if ev is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono zdarzenia zmiany.")

    scope = resolve_principal_scope(db, principal)
    if scope.restricted:
        if ev.host is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Brak dostępu do zdarzenia spoza zakresu konta.")
        scope.assert_host_allowed(ev.host)

    ev.acknowledged = payload.acknowledged
    record_audit_event(
        db,
        principal,
        action="change.acknowledge",
        resource_type="change_event",
        resource_id=str(ev.id),
        details={"acknowledged": ev.acknowledged},
    )
    db.commit()
    db.refresh(ev)
    return _serialize_event(ev)
