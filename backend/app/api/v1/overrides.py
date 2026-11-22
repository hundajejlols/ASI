from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.crypto import AAD_OVERRIDE_NOTES, decrypt_field_safe, encrypt_field
from app.core.security import Principal, require_permission
from app.db.models import AssetOverride, Host, Service
from app.db.session import get_db
from app.schemas.api import OverrideOut, OverridePatchRequest
from app.services.audit import record_audit_event
from app.services.scope import resolve_principal_scope

router = APIRouter(prefix="/overrides", tags=["overrides"])


@router.patch("", response_model=OverrideOut)
def upsert_override(
    payload: OverridePatchRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("modify")),
) -> OverrideOut:
    """
    Tworzy lub aktualizuje ręczne nadpisanie dla hosta lub usługi (asset_overrides).
    Dostępne dla ról: admin, add_delete_modify, modify_read.
    Kolejne skany nigdy nie modyfikują tej tabeli.
    """
    scope = resolve_principal_scope(db, principal)
    if payload.entity_type == "host":
        host = db.get(Host, payload.entity_id)
        if host is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Nie znaleziono hosta o podanym entity_id.",
            )
        scope.assert_host_allowed(host)
    else:
        svc = db.get(Service, payload.entity_id)
        if svc is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Nie znaleziono usługi o podanym entity_id.",
            )
        if scope.restricted:
            parent_host = db.get(Host, svc.host_id)
            if parent_host is None:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Brak dostępu do usługi spoza zakresu konta.")
            scope.assert_host_allowed(parent_host)

    ov = db.execute(
        select(AssetOverride).where(
            AssetOverride.entity_type == payload.entity_type,
            AssetOverride.entity_id == payload.entity_id,
        )
    ).scalar_one_or_none()

    if ov is None:
        ov = AssetOverride(
            entity_type=payload.entity_type,
            entity_id=payload.entity_id,
            tags=[],
        )
        db.add(ov)

    provided_fields = payload.model_fields_set
    if "custom_label" in provided_fields:
        ov.custom_label = payload.custom_label
    if "owner_unit" in provided_fields:
        ov.owner_unit = payload.owner_unit
    if "criticality" in provided_fields:
        ov.criticality = payload.criticality
    if "tags" in provided_fields and payload.tags is not None:
        ov.tags = payload.tags
    if "is_false_positive" in provided_fields and payload.is_false_positive is not None:
        ov.is_false_positive = payload.is_false_positive
    if "is_ignored" in provided_fields and payload.is_ignored is not None:
        ov.is_ignored = payload.is_ignored
    if "notes" in provided_fields:
        ov.notes_encrypted = (
            encrypt_field(payload.notes, associated_data=AAD_OVERRIDE_NOTES)
            if payload.notes
            else None
        )

    ov.updated_at = datetime.now(timezone.utc)
    record_audit_event(
        db,
        principal,
        action="override.upsert",
        resource_type=f"override:{payload.entity_type}",
        resource_id=str(payload.entity_id),
        details={
            "fields": sorted(provided_fields),
            "is_ignored": ov.is_ignored,
            "is_false_positive": ov.is_false_positive,
        },
    )
    db.commit()
    db.refresh(ov)

    notes_plain = (
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
        notes=notes_plain,
        updated_at=ov.updated_at,
    )
