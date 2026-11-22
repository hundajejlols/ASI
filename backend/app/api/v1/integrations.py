from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.crypto import AAD_INTEGRATION_TOKEN, encrypt_field
from app.core.security import Principal, require_permission
from app.db.models import Host, Integration
from app.db.session import get_db
from app.services.audit import record_audit_event
from app.services.scope import resolve_principal_scope
from app.services.defectdojo import (
    DEFAULT_ENGAGEMENT_NAME,
    DEFAULT_MAX_EXPORT_ASSETS,
    DEFAULT_PRODUCT_TYPE_NAME,
    DEFECTDOJO_INTEGRATION_NAME,
    export_to_defectdojo,
    get_defectdojo_integration,
    test_defectdojo_connection,
    validate_defectdojo_url,
)

router = APIRouter(prefix="/integrations/defectdojo", tags=["integrations"])


class DefectDojoConfigStatusOut(BaseModel):
    configured: bool
    base_url: str | None = None
    product_type_name: str = DEFAULT_PRODUCT_TYPE_NAME
    engagement_name: str = DEFAULT_ENGAGEMENT_NAME
    verify_tls: bool = True
    is_active: bool = False
    has_api_token: bool = False
    updated_at: datetime | None = None


class DefectDojoConfigPutRequest(BaseModel):
    base_url: str = Field(..., min_length=8, description="Np. https://defectdojo.agh.edu.pl")
    product_type_name: str = Field(
        default=DEFAULT_PRODUCT_TYPE_NAME,
        min_length=1,
        max_length=255,
        description="Domyślna Organizacja (Product Type) w DefectDojo dla nowo tworzonych Assetów per IP (nadpisywana przez owner_unit z asset_overrides).",
    )
    engagement_name: str = Field(
        default=DEFAULT_ENGAGEMENT_NAME,
        min_length=1,
        max_length=255,
        description="Nazwa Engagement automatycznie tworzonego w obrębie każdego Assetu (IP).",
    )
    verify_tls: bool = True
    is_active: bool = True
    api_token: str | None = Field(
        default=None,
        description="Token API v2 DefectDojo (szyfrowany AES-256-GCM + AAD; wymagany przy pierwszym zapisie).",
    )


class DefectDojoExportRequest(BaseModel):
    host_ids: list[UUID] | None = None
    scan_run_id: UUID | None = None
    only_interesting: bool = False
    close_old_findings: bool | None = None
    dry_run: bool = False
    max_assets: int = Field(default=DEFAULT_MAX_EXPORT_ASSETS, ge=1, le=5000)


def _to_status_out(integration: Integration | None) -> DefectDojoConfigStatusOut:
    if integration is None:
        return DefectDojoConfigStatusOut(configured=False)
    return DefectDojoConfigStatusOut(
        configured=True,
        base_url=integration.base_url,
        product_type_name=integration.product_type_name or DEFAULT_PRODUCT_TYPE_NAME,
        engagement_name=integration.engagement_name or DEFAULT_ENGAGEMENT_NAME,
        verify_tls=integration.verify_tls,
        is_active=integration.is_active,
        has_api_token=bool(integration.api_token_encrypted),
        updated_at=integration.updated_at,
    )


@router.get("", response_model=DefectDojoConfigStatusOut)
def get_defectdojo_config(
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("read")),
) -> DefectDojoConfigStatusOut:
    """Podgląd statusu konfiguracji DefectDojo (bez zwracania tokena API)."""
    return _to_status_out(get_defectdojo_integration(db))


@router.put("", response_model=DefectDojoConfigStatusOut)
def put_defectdojo_config(
    payload: DefectDojoConfigPutRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("manage_integrations")),
) -> DefectDojoConfigStatusOut:
    """
    Zapis/aktualizacja konfiguracji DefectDojo API v2 (tylko rola admin).
    Token API jest szyfrowany AES-256-GCM z AAD przed zapisem w PostgreSQL.
    """
    try:
        clean_base_url = validate_defectdojo_url(payload.base_url)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    clean_product_type = payload.product_type_name.strip()
    clean_engagement_name = payload.engagement_name.strip()
    if not clean_product_type:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Pole product_type_name (Organizacja / Product Type) nie może być puste.",
        )
    if not clean_engagement_name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Pole engagement_name nie może być puste.",
        )

    integration = get_defectdojo_integration(db)
    if integration is None:
        if not payload.api_token:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Pole api_token jest wymagane przy pierwszej konfiguracji DefectDojo.",
            )
        integration = Integration(
            name=DEFECTDOJO_INTEGRATION_NAME,
            provider="defectdojo",
            base_url=clean_base_url,
            api_token_encrypted=encrypt_field(payload.api_token, associated_data=AAD_INTEGRATION_TOKEN),
            product_type_name=clean_product_type,
            engagement_name=clean_engagement_name,
            verify_tls=payload.verify_tls,
            is_active=payload.is_active,
        )
        db.add(integration)
    else:
        integration.base_url = clean_base_url
        integration.product_type_name = clean_product_type
        integration.engagement_name = clean_engagement_name
        integration.verify_tls = payload.verify_tls
        integration.is_active = payload.is_active
        if payload.api_token:
            integration.api_token_encrypted = encrypt_field(payload.api_token, associated_data=AAD_INTEGRATION_TOKEN)
        integration.updated_at = datetime.now(timezone.utc)

    record_audit_event(
        db,
        principal,
        action="integration.defectdojo.config",
        resource_type="integration",
        resource_id=DEFECTDOJO_INTEGRATION_NAME,
        details={
            "base_url": clean_base_url,
            "product_type_name": clean_product_type,
            "engagement_name": clean_engagement_name,
            "token_updated": bool(payload.api_token),
        },
    )
    db.commit()
    db.refresh(integration)
    return _to_status_out(integration)


@router.post("/test")
def test_defectdojo(
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("manage_integrations")),
) -> dict[str, Any]:
    """Testuje połączenie z DefectDojo API v2 (GET /api/v2/product_types/)."""
    integration = get_defectdojo_integration(db)
    if integration is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Integracja DefectDojo nie została jeszcze skonfigurowana.",
        )
    return test_defectdojo_connection(integration)


@router.post("/export")
def export_defectdojo(
    payload: DefectDojoExportRequest = DefectDojoExportRequest(),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("modify")),
) -> dict[str, Any]:
    """
    Eksport obserwacji do DefectDojo w formacie Generic Findings Import (JSON),
    w modelu 1 IP = 1 Asset (Product).
    Dostępne dla ról: admin, add_delete_modify, modify_read.
    """
    scope = resolve_principal_scope(db, principal)
    if scope.restricted and payload.host_ids:
        req_hosts = db.execute(select(Host).where(Host.id.in_(payload.host_ids))).scalars().all()
        for h in req_hosts:
            scope.assert_host_allowed(h)

    try:
        res = export_to_defectdojo(
            db,
            host_ids=payload.host_ids,
            scan_run_id=payload.scan_run_id,
            only_interesting=payload.only_interesting,
            close_old_findings=payload.close_old_findings,
            dry_run=payload.dry_run,
            max_assets=payload.max_assets,
            scope=scope,
        )
        if not payload.dry_run:
            stats = res.get("stats") or {}
            record_audit_event(
                db,
                principal,
                action="integration.defectdojo.export",
                resource_type="defectdojo",
                resource_id=str(res.get("default_product_type_name") or ""),
                details={
                    "mode": res.get("mode"),
                    "assets_exported": stats.get("assets_exported"),
                    "assets_created": stats.get("assets_created"),
                    "assets_updated": stats.get("assets_updated"),
                    "assets_failed": stats.get("assets_failed"),
                    "findings": stats.get("total_findings"),
                },
            )
            db.commit()
        return res
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
