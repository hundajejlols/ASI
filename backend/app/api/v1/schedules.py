from datetime import datetime, time, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, selectinload

from app.core.security import Principal, require_permission
from app.db.models import ScanProfile, ScanSchedule, TargetGroup
from app.db.session import get_db
from app.services.audit import record_audit_event
from app.services.scheduler import (
    _resolve_tz,
    is_within_window,
    remaining_window_minutes,
    tick_schedules,
    validate_cron_expression,
)
from app.services.seed import ensure_default_group_and_profile

router = APIRouter(prefix="/schedules", tags=["schedules"])


def _parse_hhmm(raw: str) -> time:
    val = (raw or "").strip()
    for fmt in ("%H:%M", "%H:%M:%S"):
        try:
            return datetime.strptime(val, fmt).time()
        except ValueError:
            continue
    raise ValueError(f"Nieprawidłowy format godziny (oczekiwano HH:MM lub HH:MM:SS): {raw!r}")


class ScheduleCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    target_group_id: UUID | None = None
    profile_id: UUID | None = None
    cron_expression: str = Field(default="0 22 * * *", description="5-polowe wyrażenie cron, np. '0 22 * * *'")
    window_start: str = Field(default="22:00", description="Początek okna czasowego (HH:MM w strefie timezone)")
    window_end: str = Field(default="06:00", description="Koniec okna czasowego (HH:MM w strefie timezone)")
    timezone: str = Field(default="Europe/Warsaw")
    missed_scans_threshold: int = Field(default=3, ge=1, le=20)
    is_enabled: bool = True


class ScheduleUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=128)
    target_group_id: UUID | None = None
    cron_expression: str | None = None
    window_start: str | None = None
    window_end: str | None = None
    timezone: str | None = None
    missed_scans_threshold: int | None = Field(default=None, ge=1, le=20)
    is_enabled: bool | None = None


class ScheduleOut(BaseModel):
    id: UUID
    name: str
    target_group_id: UUID
    target_group_name: str | None = None
    target_group_type: str | None = None
    profile_id: UUID
    cron_expression: str
    window_start: str
    window_end: str
    timezone: str
    missed_scans_threshold: int
    is_enabled: bool
    in_window_now: bool
    remaining_window_minutes: int | None = None
    created_at: datetime


def _to_out(sched: ScanSchedule) -> ScheduleOut:
    now_local = datetime.now(timezone.utc).astimezone(_resolve_tz(sched.timezone))
    in_win = is_within_window(now_local, sched.window_start_utc, sched.window_end_utc)
    rem = remaining_window_minutes(now_local, sched.window_start_utc, sched.window_end_utc) if in_win else None
    grp = sched.target_group
    return ScheduleOut(
        id=sched.id,
        name=sched.name,
        target_group_id=sched.target_group_id,
        target_group_name=grp.name if grp else None,
        target_group_type=grp.group_type if grp else None,
        profile_id=sched.profile_id,
        cron_expression=sched.cron_expression,
        window_start=sched.window_start_utc.strftime("%H:%M"),
        window_end=sched.window_end_utc.strftime("%H:%M"),
        timezone=sched.timezone,
        missed_scans_threshold=sched.missed_scans_threshold,
        is_enabled=sched.is_enabled,
        in_window_now=in_win,
        remaining_window_minutes=rem,
        created_at=sched.created_at,
    )


@router.get("", response_model=list[ScheduleOut])
def list_schedules(
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("read")),
) -> list[ScheduleOut]:
    rows = db.execute(
        select(ScanSchedule)
        .options(selectinload(ScanSchedule.target_group))
        .order_by(desc(ScanSchedule.created_at))
    ).scalars().all()
    return [_to_out(r) for r in rows]


@router.post("", response_model=ScheduleOut, status_code=status.HTTP_201_CREATED)
def create_schedule(
    payload: ScheduleCreateRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("add")),
) -> ScheduleOut:
    existing = db.execute(
        select(ScanSchedule).where(ScanSchedule.name == payload.name.strip())
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Harmonogram o nazwie '{payload.name}' już istnieje.",
        )

    try:
        cron_clean = validate_cron_expression(payload.cron_expression)
        win_start = _parse_hhmm(payload.window_start)
        win_end = _parse_hhmm(payload.window_end)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    default_group, default_profile = ensure_default_group_and_profile(db)
    group = db.get(TargetGroup, payload.target_group_id) if payload.target_group_id else default_group
    if group is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono grupy celów.")

    profile = db.get(ScanProfile, payload.profile_id) if payload.profile_id else default_profile
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono profilu skanowania.")

    sched = ScanSchedule(
        name=payload.name.strip(),
        target_group_id=group.id,
        profile_id=profile.id,
        cron_expression=cron_clean,
        window_start_utc=win_start,
        window_end_utc=win_end,
        timezone=payload.timezone.strip() or "Europe/Warsaw",
        missed_scans_threshold=payload.missed_scans_threshold,
        is_enabled=payload.is_enabled,
    )
    db.add(sched)
    db.flush()
    record_audit_event(db, principal, action="schedule.create", resource_type="scan_schedule", resource_id=str(sched.id), details={"name": sched.name, "cron": cron_clean})
    db.commit()
    db.refresh(sched)
    return _to_out(sched)


@router.patch("/{schedule_id}", response_model=ScheduleOut)
def update_schedule(
    schedule_id: UUID,
    payload: ScheduleUpdateRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("modify")),
) -> ScheduleOut:
    sched = db.get(ScanSchedule, schedule_id)
    if sched is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono harmonogramu.")

    fields = payload.model_fields_set
    try:
        if "name" in fields and payload.name is not None:
            clean_name = payload.name.strip()
            if len(clean_name) < 2:
                raise ValueError("Nazwa harmonogramu musi mieć co najmniej 2 znaki.")
            conflict = db.execute(
                select(ScanSchedule).where(
                    ScanSchedule.name == clean_name,
                    ScanSchedule.id != schedule_id,
                )
            ).scalar_one_or_none()
            if conflict is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Harmonogram o nazwie '{clean_name}' już istnieje.",
                )
            sched.name = clean_name
        if "target_group_id" in fields and payload.target_group_id is not None:
            new_grp = db.get(TargetGroup, payload.target_group_id)
            if new_grp is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono grupy celów.")
            sched.target_group_id = new_grp.id
        if "cron_expression" in fields and payload.cron_expression is not None:
            sched.cron_expression = validate_cron_expression(payload.cron_expression)
        if "window_start" in fields and payload.window_start is not None:
            sched.window_start_utc = _parse_hhmm(payload.window_start)
        if "window_end" in fields and payload.window_end is not None:
            sched.window_end_utc = _parse_hhmm(payload.window_end)
        if "timezone" in fields and payload.timezone is not None:
            sched.timezone = payload.timezone.strip() or "Europe/Warsaw"
        if "missed_scans_threshold" in fields and payload.missed_scans_threshold is not None:
            sched.missed_scans_threshold = payload.missed_scans_threshold
        if "is_enabled" in fields and payload.is_enabled is not None:
            sched.is_enabled = payload.is_enabled
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    record_audit_event(db, principal, action="schedule.update", resource_type="scan_schedule", resource_id=str(sched.id), details={"fields": sorted(fields)})
    db.commit()
    db.refresh(sched)
    return _to_out(sched)


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(
    schedule_id: UUID,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("delete")),
) -> None:
    sched = db.get(ScanSchedule, schedule_id)
    if sched is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono harmonogramu.")
    sched_name = sched.name
    db.delete(sched)
    record_audit_event(db, principal, action="schedule.delete", resource_type="scan_schedule", resource_id=str(schedule_id), details={"name": sched_name})
    db.commit()


@router.post("/tick")
def trigger_scheduler_tick(
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("add")),
) -> dict[str, Any]:
    """Ręczne wyzwolenie ewaluacji harmonogramów, uzgadniania wygasłych skanów i auto-wznawiania."""
    return tick_schedules(db)
