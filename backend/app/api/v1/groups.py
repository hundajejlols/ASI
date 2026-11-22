"""
Endpointy Automatycznych Grup (Auto-Groups & Smart Groups):
  - GET  /api/v1/groups/auto         — grupy wykrywane na żywo (technologie/CMS, porty, flagi, sygnatury, jednostki/tagi) + facets
  - POST /api/v1/groups/preview      — podgląd dopasowanych hostów i portów dla dowolnych reguł filter_rules
  - POST /api/v1/groups/scan         — uruchomienie skanu (pełny profil / tylko porty grupy / własne porty) na grupie lub ad-hoc regułach
  - GET  /api/v1/groups              — lista zapisanych grup dynamicznych (lub wszystkich przy include_static=true)
  - POST /api/v1/groups              — zapis nowej grupy dynamicznej (Smart Group) w target_groups
  - GET  /api/v1/groups/{id}/members — aktualni członkowie grupy
  - PATCH/DELETE /api/v1/groups/{id} — edycja i usuwanie zapisanych grup dynamicznych
"""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.security import Principal, require_permission
from app.db.models import Target, TargetGroup
from app.db.session import get_db
from app.services.audit import record_audit_event
from app.services.chunker import start_scan_run
from app.services.groups import (
    GroupFilterRules,
    discover_auto_groups,
    resolve_hosts_by_rules,
    serialize_filter_rules,
)
from app.services.scope import ResolvedScope, resolve_principal_scope

router = APIRouter(prefix="/groups", tags=["groups"])


class DynamicGroupCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    description: str | None = None
    environment: str = Field(default="prod", max_length=32)
    filter_rules: GroupFilterRules


class DynamicGroupUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=128)
    description: str | None = None
    environment: str | None = Field(default=None, max_length=32)
    filter_rules: GroupFilterRules | None = None


class GroupScanRequest(BaseModel):
    group_id: UUID | None = Field(
        default=None,
        description="ID zapisanej grupy dynamicznej (opcjonalne — jeśli brak, używa filter_rules).",
    )
    filter_rules: GroupFilterRules | None = Field(
        default=None,
        description="Reguły ad-hoc (np. z auto-grupy) do przeskanowania bez konieczności zapisywania grupy.",
    )
    group_label: str | None = Field(default=None, max_length=128)
    profile_id: UUID | None = None
    ports_mode: Literal["profile", "matched_ports", "custom"] = Field(
        default="profile",
        description="'profile' = pełne porty z profilu skanowania (domyślnie), 'matched_ports' = tylko porty wykryte w tej grupie, 'custom' = własna specyfikacja.",
    )
    custom_ports: str | None = None
    rate_limit_pps: int | None = Field(default=None, ge=1)
    window_minutes: int = Field(default=60, ge=1, le=1440)
    dry_run: bool = False


class SavedGroupOut(BaseModel):
    id: UUID
    name: str
    description: str | None = None
    environment: str
    group_type: str
    filter_rules: dict[str, Any]
    member_count: int
    host_ids: list[str]
    sample_ips: list[str]
    matched_ports: list[int]
    suggested_ports_spec: str | None = None
    created_at: datetime


def _serialize_saved_group(db: Session, grp: TargetGroup, *, scope: ResolvedScope | None = None) -> SavedGroupOut:
    if grp.group_type == "dynamic":
        resolved = resolve_hosts_by_rules(db, grp.filter_rules, scope=scope)
        return SavedGroupOut(
            id=grp.id,
            name=grp.name,
            description=grp.description,
            environment=grp.environment,
            group_type=grp.group_type,
            filter_rules=dict(grp.filter_rules or {}),
            member_count=resolved["total_hosts"],
            host_ids=resolved["host_ids"],
            sample_ips=resolved["ips"][:8],
            matched_ports=resolved["matched_ports"],
            suggested_ports_spec=resolved["suggested_ports_spec"],
            created_at=grp.created_at,
        )

    targets = db.execute(
        select(Target).where(Target.group_id == grp.id, Target.is_active.is_(True))
    ).scalars().all()
    if scope is not None and scope.restricted:
        targets = [t for t in targets if scope.is_target_allowed(t.raw_value, t.type)]
    return SavedGroupOut(
        id=grp.id,
        name=grp.name,
        description=grp.description,
        environment=grp.environment,
        group_type=grp.group_type,
        filter_rules={},
        member_count=len(targets),
        host_ids=[],
        sample_ips=[str(t.raw_value) for t in targets[:8]],
        matched_ports=[],
        suggested_ports_spec=None,
        created_at=grp.created_at,
    )


@router.get("/auto")
def get_auto_groups(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("read")),
) -> dict[str, Any]:
    """Zwraca automatycznie wykryte grupy (technologie/CMS, otwarte porty, flagi, sygnatury, jednostki/tagi) oraz facets."""
    scope = resolve_principal_scope(db, principal)
    return discover_auto_groups(db, scope=scope)


@router.post("/preview")
def preview_group_rules(
    payload: GroupFilterRules,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("read")),
) -> dict[str, Any]:
    """Podgląd hostów i portów pasujących do wskazanych reguł grupy dynamicznej."""
    scope = resolve_principal_scope(db, principal)
    return resolve_hosts_by_rules(db, payload, scope=scope)


@router.post("/scan")
def scan_group(
    payload: GroupScanRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("add")),
) -> dict[str, Any]:
    """
    Uruchamia celowany skan (lub dry_run) na zapisanej grupie dynamicznej albo ad-hoc regułach auto-grupy.
    Domyślnie używa pełnego profilu skanowania (ports_mode='profile'); opcjonalnie 'matched_ports' lub 'custom'.
    """
    scope = resolve_principal_scope(db, principal)
    target_group_id: UUID | None = None
    group_label = (payload.group_label or "").strip()

    if payload.group_id is not None:
        grp = db.get(TargetGroup, payload.group_id)
        if grp is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono grupy docelowej.")
        if grp.group_type != "dynamic":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Ten endpoint służy do skanowania grup dynamicznych; dla grup statycznych użyj /api/v1/scans/start.",
            )
        target_group_id = grp.id
        group_label = group_label or grp.name
        resolved = resolve_hosts_by_rules(db, grp.filter_rules, scope=scope)
    elif payload.filter_rules is not None:
        resolved = resolve_hosts_by_rules(db, payload.filter_rules, scope=scope)
        group_label = group_label or "Ad-hoc Smart Group"
    else:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Podaj 'group_id' albo 'filter_rules'.",
        )

    matched_ips = resolved["ips"]
    if not matched_ips:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Grupa '{group_label}' nie dopasowuje obecnie żadnych hostów do przeskanowania.",
        )

    ports_override: str | None = None
    if payload.ports_mode == "matched_ports":
        ports_override = resolved["suggested_ports_spec"]
    elif payload.ports_mode == "custom":
        if not payload.custom_ports or not payload.custom_ports.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Tryb 'custom' wymaga podania specyfikacji portów w polu 'custom_ports'.",
            )
        ports_override = payload.custom_ports.strip()

    try:
        res = start_scan_run(
            db,
            target_group_id=target_group_id,
            raw_targets=matched_ips,
            profile_id=payload.profile_id,
            rate_limit_pps=payload.rate_limit_pps,
            ports_override=ports_override,
            window_minutes=payload.window_minutes,
            dry_run=payload.dry_run,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    if not payload.dry_run:
        record_audit_event(
            db,
            principal,
            action="group.scan",
            resource_type="target_group",
            resource_id=str(target_group_id) if target_group_id else group_label,
            details={
                "group_label": group_label,
                "ports_mode": payload.ports_mode,
                "effective_ports": res.get("ports"),
                "matched_hosts": len(matched_ips),
                "scan_run_id": res.get("scan_run_id"),
            },
        )
        db.commit()

    return {
        **res,
        "group_label": group_label,
        "ports_mode": payload.ports_mode,
        "matched_hosts_count": len(matched_ips),
        "matched_ips": matched_ips[:50],
    }


@router.get("", response_model=list[SavedGroupOut])
def list_groups(
    include_static: bool = Query(default=False, description="Gdy true, zwraca również statyczne grupy celów (np. local-lab)."),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("read")),
) -> list[SavedGroupOut]:
    scope = resolve_principal_scope(db, principal)
    stmt = select(TargetGroup).order_by(desc(TargetGroup.created_at))
    if not include_static:
        stmt = stmt.where(TargetGroup.group_type == "dynamic")
    rows = db.execute(stmt).scalars().all()
    serialized = [_serialize_saved_group(db, g, scope=scope) for g in rows]
    if scope.restricted:
        # Pokaż grupy jawnie przypisane kontu albo dopasowujące przynajmniej 1 host w zakresie konta
        serialized = [
            g for g in serialized
            if (g.id in scope.allowed_group_ids or g.member_count > 0)
        ]
    return serialized


@router.post("", response_model=SavedGroupOut, status_code=status.HTTP_201_CREATED)
def create_dynamic_group(
    payload: DynamicGroupCreateRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("add")),
) -> SavedGroupOut:
    scope = resolve_principal_scope(db, principal)
    name = payload.name.strip()
    if len(name) < 2:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Nazwa grupy musi mieć co najmniej 2 znaki.")
    if db.execute(select(TargetGroup).where(TargetGroup.name == name)).scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Grupa o nazwie '{name}' już istnieje.")

    rules_dict = serialize_filter_rules(payload.filter_rules)
    grp = TargetGroup(
        name=name,
        description=payload.description.strip() if payload.description else None,
        environment=(payload.environment or "prod").strip() or "prod",
        group_type="dynamic",
        filter_rules=rules_dict,
    )
    db.add(grp)
    db.flush()
    record_audit_event(
        db,
        principal,
        action="group.create",
        resource_type="target_group",
        resource_id=str(grp.id),
        details={"name": name, "group_type": "dynamic", "filter_rules": rules_dict},
    )
    db.commit()
    db.refresh(grp)
    return _serialize_saved_group(db, grp, scope=scope)


@router.get("/{group_id}/members")
def get_group_members(
    group_id: UUID,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("read")),
) -> dict[str, Any]:
    scope = resolve_principal_scope(db, principal)
    grp = db.get(TargetGroup, group_id)
    if grp is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono grupy.")
    if grp.group_type == "dynamic":
        resolved = resolve_hosts_by_rules(db, grp.filter_rules, scope=scope)
        return {
            "group_id": str(grp.id),
            "name": grp.name,
            "group_type": grp.group_type,
            **resolved,
        }
    targets = db.execute(
        select(Target).where(Target.group_id == grp.id, Target.is_active.is_(True))
    ).scalars().all()
    if scope.restricted:
        targets = [t for t in targets if scope.is_target_allowed(t.raw_value, t.type)]
    return {
        "group_id": str(grp.id),
        "name": grp.name,
        "group_type": grp.group_type,
        "total_hosts": len(targets),
        "host_ids": [],
        "ips": [t.raw_value for t in targets],
        "matched_ports": [],
        "suggested_ports_spec": None,
        "hosts": [],
        "truncated": False,
    }


@router.patch("/{group_id}", response_model=SavedGroupOut)
def update_dynamic_group(
    group_id: UUID,
    payload: DynamicGroupUpdateRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("modify")),
) -> SavedGroupOut:
    scope = resolve_principal_scope(db, principal)
    if scope.restricted and group_id in scope.allowed_group_ids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Nie możesz edytować reguł grupy definiującej zakres widoczności Twojego konta.",
        )
    grp = db.get(TargetGroup, group_id)
    if grp is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono grupy.")
    if grp.group_type != "dynamic":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Można edytować reguły wyłącznie grup dynamicznych (Smart Groups).",
        )

    fields = payload.model_fields_set
    if "name" in fields and payload.name is not None:
        clean_name = payload.name.strip()
        if len(clean_name) < 2:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Nazwa grupy musi mieć co najmniej 2 znaki.")
        conflict = db.execute(
            select(TargetGroup).where(TargetGroup.name == clean_name, TargetGroup.id != group_id)
        ).scalar_one_or_none()
        if conflict is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Grupa o nazwie '{clean_name}' już istnieje.")
        grp.name = clean_name
    if "description" in fields:
        grp.description = payload.description.strip() if payload.description else None
    if "environment" in fields and payload.environment is not None:
        grp.environment = payload.environment.strip() or "prod"
    if "filter_rules" in fields and payload.filter_rules is not None:
        grp.filter_rules = serialize_filter_rules(payload.filter_rules)

    record_audit_event(
        db,
        principal,
        action="group.update",
        resource_type="target_group",
        resource_id=str(grp.id),
        details={"name": grp.name, "fields": sorted(fields)},
    )
    db.commit()
    db.refresh(grp)
    return _serialize_saved_group(db, grp, scope=scope)


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_dynamic_group(
    group_id: UUID,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("delete")),
) -> None:
    scope = resolve_principal_scope(db, principal)
    if scope.restricted and group_id in scope.allowed_group_ids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Nie możesz usunąć grupy definiującej zakres widoczności Twojego konta.",
        )
    grp = db.get(TargetGroup, group_id)
    if grp is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono grupy.")
    if grp.group_type != "dynamic":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nie można usunąć statycznej grupy celów z tego endpointu.",
        )
    grp_name = grp.name
    db.delete(grp)
    record_audit_event(
        db,
        principal,
        action="group.delete",
        resource_type="target_group",
        resource_id=str(group_id),
        details={"name": grp_name},
    )
    db.commit()
