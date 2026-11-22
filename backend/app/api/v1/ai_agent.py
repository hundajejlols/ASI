"""
Endpointy pasywnego AI Security Agenta (OpenRouter — tryb READ-ONLY):
  - GET    /api/v1/ai-agent/config                 — status konfiguracji (bez zwracania klucza API)
  - PUT    /api/v1/ai-agent/config                 — zapis klucza OpenRouter (AES-256-GCM + AAD) i modelu
  - DELETE /api/v1/ai-agent/config                 — usunięcie zapisanego klucza API
  - POST   /api/v1/ai-agent/test                   — test klucza OpenRouter (/auth/key, 0 tokenów)
  - GET    /api/v1/ai-agent/alerts                 — lista najnowszych alertów/ocen AI (z poszanowaniem Asset Scope)
  - POST   /api/v1/ai-agent/analyze                — analiza wybranych lub wszystkich widocznych hostów
  - PATCH  /api/v1/ai-agent/alerts/{id}/acknowledge — oznaczenie alertu jako zaalarmowano / potwierdzono
"""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, selectinload

from app.core.crypto import AAD_AI_AGENT_KEY, encrypt_field
from app.core.security import Principal, require_permission
from app.db.models import AiAgentConfig, AiAlert, AssetOverride, Host
from app.db.session import get_db
from app.services.ai_agent import (
    DEFAULT_OPENROUTER_BASE_URL,
    DEFAULT_OPENROUTER_MODEL,
    POPULAR_OPENROUTER_MODELS,
    analyze_hosts_with_ai,
    get_ai_agent_config,
    list_latest_ai_alerts,
    serialize_ai_alert,
    test_openrouter_connection,
)
from app.services.audit import record_audit_event
from app.services.scope import resolve_principal_scope

router = APIRouter(prefix="/ai-agent", tags=["ai-agent"])


class AiAgentConfigOut(BaseModel):
    configured: bool
    provider: str = "openrouter"
    base_url: str = DEFAULT_OPENROUTER_BASE_URL
    model_name: str = DEFAULT_OPENROUTER_MODEL
    has_api_key: bool = False
    auto_analyze_after_scan: bool = True
    is_active: bool = False
    updated_at: datetime | None = None
    popular_models: list[dict[str, str]] = Field(default_factory=lambda: list(POPULAR_OPENROUTER_MODELS))


class AiAgentConfigPutRequest(BaseModel):
    api_key: str | None = Field(
        default=None,
        description="Klucz API OpenRouter (sk-or-v1-...); szyfrowany AES-256-GCM + AAD, wymagany przy pierwszym zapisie.",
    )
    model_name: str = Field(default=DEFAULT_OPENROUTER_MODEL, min_length=2, max_length=128)
    auto_analyze_after_scan: bool = True
    is_active: bool = True


class AiAnalyzeRequest(BaseModel):
    host_ids: list[UUID] | None = Field(
        default=None,
        description="Opcjonalna lista ID hostów do analizy (jeśli brak, analizuje wszystkie widoczne hosty w zakresie konta).",
    )
    max_hosts: int = Field(default=25, ge=1, le=50)


class AiAlertAckRequest(BaseModel):
    acknowledged: bool = True


def _serialize_config(cfg: AiAgentConfig | None) -> AiAgentConfigOut:
    if cfg is None:
        return AiAgentConfigOut(configured=False)
    return AiAgentConfigOut(
        configured=bool(cfg.api_key_encrypted),
        provider=cfg.provider,
        base_url=cfg.base_url,
        model_name=cfg.model_name,
        has_api_key=bool(cfg.api_key_encrypted),
        auto_analyze_after_scan=bool(cfg.auto_analyze_after_scan),
        is_active=bool(cfg.is_active),
        updated_at=cfg.updated_at,
    )


@router.get("/config", response_model=AiAgentConfigOut)
def get_config(
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("read")),
) -> AiAgentConfigOut:
    return _serialize_config(get_ai_agent_config(db))


@router.put("/config", response_model=AiAgentConfigOut)
def save_config(
    payload: AiAgentConfigPutRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("manage_integrations")),
) -> AiAgentConfigOut:
    if principal.scope_restricted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Konfiguracja klucza AI Agenta wymaga administratora z pełnym dostępem.",
        )

    clean_model = payload.model_name.strip()
    if not clean_model or "/" not in clean_model:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Podaj nazwę modelu OpenRouter w formacie 'dostawca/model' (np. 'google/gemini-2.5-flash').",
        )

    clean_key = (payload.api_key or "").strip()
    cfg = get_ai_agent_config(db)
    if cfg is None:
        if not clean_key:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Podaj klucz API OpenRouter przy pierwszej konfiguracji.",
            )
        cfg = AiAgentConfig(
            id="default",
            provider="openrouter",
            base_url=DEFAULT_OPENROUTER_BASE_URL,
            model_name=clean_model,
            api_key_encrypted=encrypt_field(clean_key, associated_data=AAD_AI_AGENT_KEY),
            auto_analyze_after_scan=payload.auto_analyze_after_scan,
            is_active=payload.is_active,
        )
        db.add(cfg)
    else:
        cfg.model_name = clean_model
        cfg.auto_analyze_after_scan = payload.auto_analyze_after_scan
        cfg.is_active = payload.is_active
        if clean_key:
            cfg.api_key_encrypted = encrypt_field(clean_key, associated_data=AAD_AI_AGENT_KEY)
        cfg.updated_at = datetime.now(timezone.utc)

    record_audit_event(
        db,
        principal,
        action="ai_agent.config.save",
        resource_type="ai_agent",
        resource_id="default",
        details={
            "provider": "openrouter",
            "model_name": clean_model,
            "auto_analyze_after_scan": payload.auto_analyze_after_scan,
            "key_updated": bool(clean_key),
        },
    )
    db.commit()
    db.refresh(cfg)
    return _serialize_config(cfg)


@router.delete("/config", status_code=status.HTTP_204_NO_CONTENT)
def delete_config(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("manage_integrations")),
) -> None:
    if principal.scope_restricted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usunięcie klucza AI Agenta wymaga administratora z pełnym dostępem.",
        )
    cfg = get_ai_agent_config(db)
    if cfg is not None:
        db.delete(cfg)
        record_audit_event(
            db,
            principal,
            action="ai_agent.config.delete",
            resource_type="ai_agent",
            resource_id="default",
        )
        db.commit()


@router.post("/test")
def test_config(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("manage_integrations")),
) -> dict[str, Any]:
    if principal.scope_restricted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Test połączenia AI Agenta wymaga administratora z pełnym dostępem.",
        )
    cfg = get_ai_agent_config(db)
    if cfg is None or not cfg.api_key_encrypted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Klucz API OpenRouter nie został jeszcze zapisany.",
        )
    return test_openrouter_connection(cfg)


@router.get("/alerts")
def get_alerts(
    host_id: UUID | None = Query(default=None),
    only_urgent: bool = Query(default=False),
    limit: int = Query(default=200, ge=1, le=500),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("read")),
) -> dict[str, Any]:
    """Zwraca najnowsze oceny i alerty AI Agenta dla hostów widocznych w zakresie konta."""
    scope = resolve_principal_scope(db, principal)
    if host_id is not None and scope.restricted:
        host = db.get(Host, host_id)
        if host is not None:
            scope.assert_host_allowed(host)

    alerts = list_latest_ai_alerts(
        db,
        scope=scope,
        host_id=host_id,
        only_urgent=only_urgent,
        limit=limit,
    )
    urgent_unack = sum(1 for a in alerts if a["requires_admin_alert"] and not a["acknowledged"])
    vulnerable_cnt = sum(1 for a in alerts if a["urgency"] in ("critical", "high", "medium"))
    safe_cnt = sum(1 for a in alerts if a["urgency"] in ("safe", "low"))
    return {
        "summary": {
            "total": len(alerts),
            "urgent_unacknowledged": urgent_unack,
            "vulnerable_or_outdated": vulnerable_cnt,
            "safe_or_low": safe_cnt,
        },
        "alerts": alerts,
    }


@router.post("/analyze")
def trigger_ai_analysis(
    payload: AiAnalyzeRequest = AiAnalyzeRequest(),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("modify")),
) -> dict[str, Any]:
    """
    Uruchamia pasywną analizę AI (READ-ONLY) wykrytych wersji oprogramowania dla wybranych
    albo wszystkich widocznych hostów w zakresie konta.
    """
    scope = resolve_principal_scope(db, principal)
    if scope.restricted and payload.host_ids:
        req_hosts = db.execute(select(Host).where(Host.id.in_(payload.host_ids))).scalars().all()
        for h in req_hosts:
            scope.assert_host_allowed(h)

    try:
        res = analyze_hosts_with_ai(
            db,
            host_ids=payload.host_ids,
            scope=scope,
            max_hosts=payload.max_hosts,
            require_configured_key=True,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    record_audit_event(
        db,
        principal,
        action="ai_agent.analyze",
        resource_type="ai_agent",
        resource_id=str(payload.host_ids[0]) if (payload.host_ids and len(payload.host_ids) == 1) else "batch",
        details={
            "analyzed_count": res["analyzed_count"],
            "urgent_alerts_count": res["urgent_alerts_count"],
            "fallback_count": res["fallback_count"],
        },
    )
    db.commit()
    return res


@router.patch("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: UUID,
    payload: AiAlertAckRequest = AiAlertAckRequest(),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("modify")),
) -> dict[str, Any]:
    """Oznacza alert AI jako przekazany administratorowi / potwierdzony."""
    alert = db.execute(
        select(AiAlert).where(AiAlert.id == alert_id).options(selectinload(AiAlert.host))
    ).scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono alertu AI.")

    scope = resolve_principal_scope(db, principal)
    if scope.restricted:
        if alert.host is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Brak dostępu do alertu spoza zakresu konta.")
        scope.assert_host_allowed(alert.host)

    alert.acknowledged = payload.acknowledged
    alert.acknowledged_at = datetime.now(timezone.utc) if payload.acknowledged else None
    alert.acknowledged_by = principal.username if payload.acknowledged else None

    record_audit_event(
        db,
        principal,
        action="ai_agent.alert.acknowledge",
        resource_type="ai_alert",
        resource_id=str(alert.id),
        details={"host_id": str(alert.host_id), "acknowledged": alert.acknowledged},
    )
    db.commit()
    db.refresh(alert)

    ov = db.execute(
        select(AssetOverride).where(
            AssetOverride.entity_type == "host",
            AssetOverride.entity_id == alert.host_id,
        )
    ).scalar_one_or_none()
    return serialize_ai_alert(alert, ov)


@router.delete("/alerts")
def clear_alerts(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("modify")),
) -> dict[str, Any]:
    """
    Czyści zapisane oceny i alerty AI (w zakresie widocznym dla konta),
    zachowując zapisany klucz API OpenRouter i nie modyfikując hostów.
    """
    scope = resolve_principal_scope(db, principal)
    scope_flt = scope.sql_host_filter()

    if scope_flt is not None:
        allowed_host_ids = list(db.execute(select(Host.id).where(scope_flt)).scalars().all())
        if not allowed_host_ids:
            return {"deleted": 0}
        res = db.execute(delete(AiAlert).where(AiAlert.host_id.in_(allowed_host_ids)))
    else:
        res = db.execute(delete(AiAlert))

    deleted_count = int(res.rowcount or 0)
    record_audit_event(
        db,
        principal,
        action="ai_agent.alerts.clear",
        resource_type="ai_alert",
        resource_id="all",
        details={"deleted": deleted_count},
    )
    db.commit()
    return {"deleted": deleted_count}
