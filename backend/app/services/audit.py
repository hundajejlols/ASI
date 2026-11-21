"""
Rejestr zdarzeń audytowych (audit_logs) dla operacji administracyjnych i modyfikacji w ASI.
"""

from typing import Any
from sqlalchemy.orm import Session

from app.core.security import Principal
from app.db.models import AuditLog


def record_audit_event(
    db: Session,
    principal: Principal | None,
    *,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Dodaje wpis do tabeli audit_logs (bez własnego commita — zatwierdzany z główną transakcją)."""
    payload = dict(details or {})
    if principal is not None:
        payload.setdefault("actor", principal.username)
        payload.setdefault("role", principal.role)
        payload.setdefault("auth_mode", principal.auth_mode)
    db.add(
        AuditLog(
            user_id=principal.user_id if principal else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=payload,
        )
    )
