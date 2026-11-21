"""
Endpointy uwierzytelniania JWT (/auth/*), zarządzania rolami RBAC i użytkownikami (/rbac/*)
oraz dziennika audytu (/audit-logs).
"""

from datetime import datetime
import re
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.security import (
    ALL_PERMISSIONS,
    BUILTIN_ROLE_PERMS_BY_NAME,
    Principal,
    create_access_token,
    get_current_principal,
    hash_password,
    require_permission,
    resolve_role_permissions,
    verify_password,
)
from app.db.models import AuditLog, RbacRole, User
from app.db.session import get_db
from app.services.audit import record_audit_event

router = APIRouter(tags=["auth-rbac"])

ROLE_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{1,62}$")


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str
    permissions: list[str]


class PrincipalOut(BaseModel):
    username: str
    role: str
    permissions: list[str]
    auth_mode: str


class RoleOut(BaseModel):
    name: str
    description: str | None = None
    permissions: list[str]
    is_system: bool
    created_at: datetime | None = None


class RoleCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=63, description="Np. soc_auditor, scanner_bot")
    description: str | None = None
    permissions: list[str] = Field(..., min_length=1)


class RoleUpdateRequest(BaseModel):
    description: str | None = None
    permissions: list[str] | None = None


class UserOut(BaseModel):
    id: UUID
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=64)
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=6, max_length=128)
    role_name: str = Field(default="read_only")


class AuditLogOut(BaseModel):
    id: int
    user_id: UUID | None = None
    action: str
    resource_type: str
    resource_id: str | None = None
    details: dict[str, Any]
    created_at: datetime


def _validate_permissions(perms: list[str]) -> list[str]:
    cleaned = sorted({p.strip() for p in perms if p and p.strip()})
    unknown = [p for p in cleaned if p not in ALL_PERMISSIONS]
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Nieznane uprawnienia: {unknown}. Dozwolone: {sorted(ALL_PERMISSIONS)}",
        )
    if not cleaned:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Rola musi posiadać co najmniej jedno uprawnienie (np. 'read').",
        )
    return cleaned


@router.post("/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    """Logowanie użytkownika z tabeli `users` i wydanie podpisanego tokena JWT (HS256)."""
    user = db.execute(select(User).where(User.username == payload.username.strip())).scalar_one_or_none()
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nieprawidłowa nazwa użytkownika lub hasło.",
        )

    effective_role = user.custom_role_name or user.role
    perms = resolve_role_permissions(db, effective_role) or {"read"}
    token = create_access_token(user_id=user.id, username=user.username, role=effective_role)

    principal = Principal(
        username=user.username,
        role=effective_role,
        permissions=frozenset(perms),
        auth_mode="jwt",
        user_id=user.id,
    )
    record_audit_event(
        db,
        principal,
        action="auth.login",
        resource_type="user",
        resource_id=str(user.id),
        details={"username": user.username},
    )
    db.commit()

    return LoginResponse(
        access_token=token,
        username=user.username,
        role=effective_role,
        permissions=sorted(perms),
    )


@router.get("/auth/me", response_model=PrincipalOut)
def get_me(principal: Principal = Depends(get_current_principal)) -> PrincipalOut:
    return PrincipalOut(
        username=principal.username,
        role=principal.role,
        permissions=sorted(principal.permissions),
        auth_mode=principal.auth_mode,
    )


@router.get("/rbac/roles", response_model=list[RoleOut])
def list_roles(
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("read")),
) -> list[RoleOut]:
    rows = db.execute(select(RbacRole).order_by(RbacRole.is_system.desc(), RbacRole.name)).scalars().all()
    if not rows:
        return [
            RoleOut(name=k, permissions=sorted(v), is_system=True)
            for k, v in BUILTIN_ROLE_PERMS_BY_NAME.items()
        ]
    return [
        RoleOut(
            name=r.name,
            description=r.description,
            permissions=list(r.permissions or []),
            is_system=r.is_system,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.post("/rbac/roles", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
def create_role(
    payload: RoleCreateRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("manage_users")),
) -> RoleOut:
    """Tworzy nową własną rolę RBAC (tylko administrator)."""
    name = payload.name.strip().lower()
    if not ROLE_NAME_RE.match(name):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Nazwa roli musi zaczynać się od małej litery i zawierać wyłącznie [a-z0-9_-] (2-63 znaki).",
        )
    if db.get(RbacRole, name) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Rola RBAC '{name}' już istnieje.",
        )

    perms = _validate_permissions(payload.permissions)
    role = RbacRole(
        name=name,
        description=payload.description.strip() if payload.description else None,
        permissions=perms,
        is_system=False,
    )
    db.add(role)
    record_audit_event(
        db,
        principal,
        action="rbac.role.create",
        resource_type="rbac_role",
        resource_id=name,
        details={"permissions": perms},
    )
    db.commit()
    db.refresh(role)
    return RoleOut(
        name=role.name,
        description=role.description,
        permissions=list(role.permissions or []),
        is_system=role.is_system,
        created_at=role.created_at,
    )


@router.patch("/rbac/roles/{role_name}", response_model=RoleOut)
def update_role(
    role_name: str,
    payload: RoleUpdateRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("manage_users")),
) -> RoleOut:
    role = db.get(RbacRole, role_name)
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono roli RBAC.")
    if role.name == "admin" and payload.permissions is not None and "manage_users" not in payload.permissions:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Nie można odebrać uprawnienia 'manage_users' roli systemowej 'admin'.",
        )
    if "description" in payload.model_fields_set:
        role.description = payload.description.strip() if payload.description else None
    if "permissions" in payload.model_fields_set and payload.permissions is not None:
        role.permissions = _validate_permissions(payload.permissions)

    record_audit_event(
        db,
        principal,
        action="rbac.role.update",
        resource_type="rbac_role",
        resource_id=role.name,
        details={"permissions": role.permissions},
    )
    db.commit()
    db.refresh(role)
    return RoleOut(
        name=role.name,
        description=role.description,
        permissions=list(role.permissions or []),
        is_system=role.is_system,
        created_at=role.created_at,
    )


@router.delete("/rbac/roles/{role_name}", status_code=status.HTTP_204_NO_CONTENT)
def delete_role(
    role_name: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("manage_users")),
) -> None:
    role = db.get(RbacRole, role_name)
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono roli RBAC.")
    if role.is_system:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nie można usunąć wbudowanej roli systemowej.",
        )
    db.delete(role)
    record_audit_event(
        db,
        principal,
        action="rbac.role.delete",
        resource_type="rbac_role",
        resource_id=role_name,
    )
    db.commit()


@router.get("/rbac/users", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("manage_users")),
) -> list[UserOut]:
    users = db.execute(select(User).order_by(User.created_at)).scalars().all()
    return [
        UserOut(
            id=u.id,
            username=u.username,
            email=u.email,
            role=u.custom_role_name or u.role,
            is_active=u.is_active,
            created_at=u.created_at,
        )
        for u in users
    ]


@router.post("/rbac/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("manage_users")),
) -> UserOut:
    uname = payload.username.strip()
    email = payload.email.strip().lower()
    if db.execute(select(User).where(User.username == uname)).scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Użytkownik '{uname}' już istnieje.")
    if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Email '{email}' już istnieje.")

    role_name = payload.role_name.strip().lower()
    if db.get(RbacRole, role_name) is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Nieznana rola RBAC: {role_name}")

    enum_role = role_name if role_name in BUILTIN_ROLE_PERMS_BY_NAME else "read_only"
    user = User(
        username=uname,
        email=email,
        password_hash=hash_password(payload.password),
        role=enum_role,
        custom_role_name=role_name,
        is_active=True,
    )
    db.add(user)
    db.flush()
    record_audit_event(
        db,
        principal,
        action="rbac.user.create",
        resource_type="user",
        resource_id=str(user.id),
        details={"username": uname, "role": role_name},
    )
    db.commit()
    db.refresh(user)
    return UserOut(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.custom_role_name or user.role,
        is_active=user.is_active,
        created_at=user.created_at,
    )


@router.get("/audit-logs", response_model=list[AuditLogOut])
def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("manage_users")),
) -> list[AuditLogOut]:
    rows = db.execute(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit)).scalars().all()
    return [
        AuditLogOut(
            id=r.id,
            user_id=r.user_id,
            action=r.action,
            resource_type=r.resource_type,
            resource_id=r.resource_id,
            details=dict(r.details or {}),
            created_at=r.created_at,
        )
        for r in rows
    ]
