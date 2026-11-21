import csv
import io
import json
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import Principal, require_permission
from app.db.models import Target, TargetGroup
from app.db.session import get_db
from app.services.audit import record_audit_event
from app.services.chunker import detect_target_type
from app.services.seed import ensure_default_group_and_profile

router = APIRouter(prefix="/targets", tags=["targets"])


class TargetCreateRequest(BaseModel):
    raw_value: str
    group_id: UUID | None = None
    is_active: bool = True


class TargetUpdateRequest(BaseModel):
    raw_value: str | None = None
    is_active: bool | None = None


class TargetOut(BaseModel):
    id: UUID
    group_id: UUID
    raw_value: str
    type: str
    is_active: bool
    created_at: datetime


class TargetGroupCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    description: str | None = None
    environment: str = Field(default="prod", max_length=32)


class TargetGroupOut(BaseModel):
    id: UUID
    name: str
    description: str | None = None
    environment: str
    created_at: datetime


def _resolve_group(db: Session, group_id: UUID | None) -> TargetGroup:
    if group_id is not None:
        group = db.get(TargetGroup, group_id)
        if group is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono grupy celów.")
        return group
    group, _ = ensure_default_group_and_profile(db)
    db.commit()
    return group


def _detect_csv_delimiter(content: str) -> str:
    first_line = content.splitlines()[0] if content else ""
    try:
        dialect = csv.Sniffer().sniff(content[:4096], delimiters=",;\t")
        return dialect.delimiter
    except csv.Error:
        if ";" in first_line and "," not in first_line:
            return ";"
        if "\t" in first_line and "," not in first_line:
            return "\t"
        return ","


@router.get("/groups", response_model=list[TargetGroupOut])
def list_target_groups(
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("read")),
) -> list[TargetGroupOut]:
    rows = db.execute(select(TargetGroup).order_by(TargetGroup.created_at)).scalars().all()
    return [
        TargetGroupOut(
            id=g.id,
            name=g.name,
            description=g.description,
            environment=g.environment,
            created_at=g.created_at,
        )
        for g in rows
    ]


@router.post("/groups", response_model=TargetGroupOut, status_code=status.HTTP_201_CREATED)
def create_target_group(
    payload: TargetGroupCreateRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("add")),
) -> TargetGroupOut:
    name = payload.name.strip()
    if db.execute(select(TargetGroup).where(TargetGroup.name == name)).scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Grupa celów '{name}' już istnieje.")
    grp = TargetGroup(name=name, description=payload.description, environment=payload.environment.strip() or "prod")
    db.add(grp)
    db.flush()
    record_audit_event(db, principal, action="target_group.create", resource_type="target_group", resource_id=str(grp.id), details={"name": name})
    db.commit()
    db.refresh(grp)
    return TargetGroupOut(
        id=grp.id,
        name=grp.name,
        description=grp.description,
        environment=grp.environment,
        created_at=grp.created_at,
    )


@router.get("", response_model=list[TargetOut])
def list_targets(
    group_id: UUID | None = Query(default=None),
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("read")),
) -> list[TargetOut]:
    stmt = select(Target).order_by(Target.created_at.desc())
    if group_id is not None:
        stmt = stmt.where(Target.group_id == group_id)
    rows = db.execute(stmt).scalars().all()
    return [
        TargetOut(
            id=r.id,
            group_id=r.group_id,
            raw_value=r.raw_value,
            type=r.type,
            is_active=r.is_active,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.post("", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
def create_target(
    payload: TargetCreateRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("add")),
) -> TargetOut:
    group = _resolve_group(db, payload.group_id)
    try:
        normalized, target_type = detect_target_type(payload.raw_value)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    existing = db.execute(
        select(Target).where(Target.group_id == group.id, Target.raw_value == normalized)
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cel '{normalized}' już istnieje w grupie.")

    target = Target(
        group_id=group.id,
        raw_value=normalized,
        type=target_type,
        is_active=payload.is_active,
    )
    db.add(target)
    db.flush()
    record_audit_event(db, principal, action="target.create", resource_type="target", resource_id=str(target.id), details={"raw_value": normalized, "type": target_type})
    db.commit()
    db.refresh(target)
    return TargetOut(
        id=target.id,
        group_id=target.group_id,
        raw_value=target.raw_value,
        type=target.type,
        is_active=target.is_active,
        created_at=target.created_at,
    )


@router.patch("/{target_id}", response_model=TargetOut)
def update_target(
    target_id: UUID,
    payload: TargetUpdateRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("modify")),
) -> TargetOut:
    """Edycja istniejącego celu (zmiana adresu/CIDR/domeny lub aktywacja/dezaktywacja)."""
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono celu.")

    fields = payload.model_fields_set
    if "raw_value" in fields and payload.raw_value is not None:
        try:
            normalized, target_type = detect_target_type(payload.raw_value)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
        conflict = db.execute(
            select(Target).where(
                Target.group_id == target.group_id,
                Target.raw_value == normalized,
                Target.id != target_id,
            )
        ).scalar_one_or_none()
        if conflict is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cel '{normalized}' już istnieje w grupie.")
        target.raw_value = normalized
        target.type = target_type

    if "is_active" in fields and payload.is_active is not None:
        target.is_active = payload.is_active

    record_audit_event(db, principal, action="target.update", resource_type="target", resource_id=str(target.id), details={"raw_value": target.raw_value, "is_active": target.is_active})
    db.commit()
    db.refresh(target)
    return TargetOut(
        id=target.id,
        group_id=target.group_id,
        raw_value=target.raw_value,
        type=target.type,
        is_active=target.is_active,
        created_at=target.created_at,
    )


@router.post("/import")
async def import_targets(
    file: UploadFile = File(...),
    group_id: UUID | None = Query(default=None),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("add")),
) -> dict:
    """
    Import celów z pliku CSV (z autodetekcją separatora ',', ';', '\\t')
    albo JSON (lista stringów lub obiektów z polem 'raw_value'/'target').
    """
    group = _resolve_group(db, group_id)
    content = (await file.read()).decode("utf-8-sig", errors="replace").strip()
    if not content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Przesłany plik celów jest pusty.")
    filename = (file.filename or "").lower()

    raw_items: list[str] = []
    if filename.endswith(".json") or content.startswith("[") or content.startswith("{"):
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Błędny JSON: {exc}") from exc
        if isinstance(data, dict) and "targets" in data:
            data = data["targets"]
        if not isinstance(data, list):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="JSON musi zawierać listę celów.")
        for entry in data:
            if isinstance(entry, str):
                raw_items.append(entry)
            elif isinstance(entry, dict):
                val = (
                    entry.get("raw_value")
                    or entry.get("target")
                    or entry.get("ip")
                    or entry.get("cidr")
                    or entry.get("domain")
                    or entry.get("hostname")
                    or entry.get("host")
                )
                if val:
                    raw_items.append(str(val))
    else:
        delimiter = _detect_csv_delimiter(content)
        reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)
        if reader.fieldnames and any(
            f.strip().lower() in ("target", "raw_value", "ip", "cidr", "host", "domain", "hostname")
            for f in reader.fieldnames
        ):
            for row in reader:
                norm_row = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
                val = (
                    norm_row.get("raw_value")
                    or norm_row.get("target")
                    or norm_row.get("cidr")
                    or norm_row.get("ip")
                    or norm_row.get("domain")
                    or norm_row.get("hostname")
                    or norm_row.get("host")
                )
                if val:
                    raw_items.append(val)
        else:
            for row in csv.reader(io.StringIO(content), delimiter=delimiter):
                if row and row[0].strip():
                    raw_items.append(row[0].strip())

    existing_vals = set(
        db.execute(select(Target.raw_value).where(Target.group_id == group.id)).scalars().all()
    )

    added = 0
    skipped = 0
    errors: list[str] = []

    for item in raw_items:
        try:
            normalized, target_type = detect_target_type(item)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if normalized in existing_vals:
            skipped += 1
            continue
        db.add(Target(group_id=group.id, raw_value=normalized, type=target_type, is_active=True))
        existing_vals.add(normalized)
        added += 1

    record_audit_event(
        db,
        principal,
        action="target.import",
        resource_type="target_group",
        resource_id=str(group.id),
        details={"filename": file.filename, "added": added, "skipped_duplicates": skipped, "errors_count": len(errors)},
    )
    db.commit()
    return {
        "group_id": str(group.id),
        "added": added,
        "skipped_duplicates": skipped,
        "errors": errors,
    }


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(
    target_id: UUID,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("delete")),
) -> None:
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono celu.")
    raw_val = target.raw_value
    db.delete(target)
    record_audit_event(db, principal, action="target.delete", resource_type="target", resource_id=str(target_id), details={"raw_value": raw_val})
    db.commit()
