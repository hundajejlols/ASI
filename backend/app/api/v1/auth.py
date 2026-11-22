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
from app.db.models import AuditLog, Host, RbacRole, TargetGroup, User
from app.db.session import get_db
from app.services.audit import record_audit_event
from app.services.scope import (
    UserScopeConfig,
    parse_user_scope,
    serialize_user_scope,
    summarize_user_scope,
)

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
    scope_restricted: bool = False
    scope_summary: dict[str, Any] | None = None


class PrincipalOut(BaseModel):
    username: str
    role: str
    permissions: list[str]
    auth_mode: str
    scope_restricted: bool = False
    scope_summary: dict[str, Any] | None = None


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
    scope_restricted: bool = False
    allowed_scope: dict[str, Any] = Field(default_factory=dict)
    scope_summary: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=64)
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=6, max_length=128)
    role_name: str = Field(default="read_only")
    scope_restricted: bool = False
    allowed_scope: UserScopeConfig = Field(default_factory=UserScopeConfig)


class UserUpdateRequest(BaseModel):
    email: str | None = Field(default=None, min_length=5, max_length=255)
    role_name: str | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=6, max_length=128)
    scope_restricted: bool | None = None
    allowed_scope: UserScopeConfig | None = None


class UserScopePreviewRequest(BaseModel):
    scope_restricted: bool = True
    allowed_scope: UserScopeConfig = Field(default_factory=UserScopeConfig)


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
        scope_restricted=bool(user.scope_restricted),
        allowed_scope=dict(user.allowed_scope or {}),
    )
    record_audit_event(
        db,
        principal,
        action="auth.login",
        resource_type="user",
        resource_id=str(user.id),
        details={"username": user.username, "scope_restricted": bool(user.scope_restricted)},
    )
    db.commit()

    scope_summary = summarize_user_scope(
        db,
        scope_restricted=bool(user.scope_restricted),
        raw_scope=user.allowed_scope,
    )
    return LoginResponse(
        access_token=token,
        username=user.username,
        role=effective_role,
        permissions=sorted(perms),
        scope_restricted=bool(user.scope_restricted),
        scope_summary=scope_summary,
    )


@router.get("/auth/me", response_model=PrincipalOut)
def get_me(
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> PrincipalOut:
    scope_summary = summarize_user_scope(
        db,
        scope_restricted=principal.scope_restricted,
        raw_scope=principal.allowed_scope,
    )
    return PrincipalOut(
        username=principal.username,
        role=principal.role,
        permissions=sorted(principal.permissions),
        auth_mode=principal.auth_mode,
        scope_restricted=principal.scope_restricted,
        scope_summary=scope_summary,
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


def _serialize_user(db: Session, u: User) -> UserOut:
    try:
        norm_scope = serialize_user_scope(parse_user_scope(u.allowed_scope))
    except Exception:
        norm_scope = serialize_user_scope(UserScopeConfig())
    summary = summarize_user_scope(
        db,
        scope_restricted=bool(u.scope_restricted),
        raw_scope=norm_scope,
    )
    return UserOut(
        id=u.id,
        username=u.username,
        email=u.email,
        role=u.custom_role_name or u.role,
        is_active=u.is_active,
        scope_restricted=bool(u.scope_restricted),
        allowed_scope=norm_scope,
        scope_summary=summary,
        created_at=u.created_at,
    )


def _validate_scope_references(db: Session, cfg: UserScopeConfig) -> dict[str, Any]:
    if cfg.group_ids:
        existing_gids = set(
            db.execute(select(TargetGroup.id).where(TargetGroup.id.in_(cfg.group_ids))).scalars().all()
        )
        missing_gids = [str(gid) for gid in cfg.group_ids if gid not in existing_gids]
        if missing_gids:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Nie znaleziono przypisanych grup o ID: {', '.join(missing_gids[:3])}",
            )
    if cfg.host_ids:
        existing_hids = set(
            db.execute(select(Host.id).where(Host.id.in_(cfg.host_ids))).scalars().all()
        )
        missing_hids = [str(hid) for hid in cfg.host_ids if hid not in existing_hids]
        if missing_hids:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Nie znaleziono przypisanych hostów o ID: {', '.join(missing_hids[:3])}",
            )
    return serialize_user_scope(cfg)


def _count_other_unrestricted_admins(db: Session, exclude_user_id: UUID) -> int:
    rows = db.execute(
        select(User).where(User.id != exclude_user_id, User.is_active.is_(True), User.scope_restricted.is_(False))
    ).scalars().all()
    count = 0
    for u in rows:
        eff_role = u.custom_role_name or u.role
        perms = resolve_role_permissions(db, eff_role) or set()
        if "manage_users" in perms:
            count += 1
    return count


@router.get("/rbac/users", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("manage_users")),
) -> list[UserOut]:
    users = db.execute(select(User).order_by(User.created_at)).scalars().all()
    if principal.scope_restricted and principal.user_id is not None:
        users = [u for u in users if u.id == principal.user_id]
    return [_serialize_user(db, u) for u in users]


@router.post("/rbac/users/scope-preview")
def preview_user_scope(
    payload: UserScopePreviewRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("manage_users")),
) -> dict[str, Any]:
    """Podgląd na żywo, ile hostów w bazie będzie widocznych dla danego zakresu konta."""
    if principal.scope_restricted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Konto z ograniczonym zakresem nie może konfigurować zakresów widoczności użytkowników.",
        )
    norm_scope = _validate_scope_references(db, payload.allowed_scope)
    summary = summarize_user_scope(
        db,
        scope_restricted=payload.scope_restricted,
        raw_scope=norm_scope,
    )
    return {
        "scope_restricted": payload.scope_restricted,
        "allowed_scope": norm_scope,
        "scope_summary": summary,
    }


@router.post("/rbac/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("manage_users")),
) -> UserOut:
    if principal.scope_restricted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Konto z ograniczonym zakresem widoczności nie może tworzyć nowych użytkowników.",
        )
    uname = payload.username.strip()
    email = payload.email.strip().lower()
    if db.execute(select(User).where(User.username == uname)).scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Użytkownik '{uname}' już istnieje.")
    if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Email '{email}' już istnieje.")

    role_name = payload.role_name.strip().lower()
    if db.get(RbacRole, role_name) is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Nieznana rola RBAC: {role_name}")

    norm_scope = _validate_scope_references(db, payload.allowed_scope)
    enum_role = role_name if role_name in BUILTIN_ROLE_PERMS_BY_NAME else "read_only"
    user = User(
        username=uname,
        email=email,
        password_hash=hash_password(payload.password),
        role=enum_role,
        custom_role_name=role_name,
        scope_restricted=payload.scope_restricted,
        allowed_scope=norm_scope,
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
        details={
            "username": uname,
            "role": role_name,
            "scope_restricted": payload.scope_restricted,
        },
    )
    db.commit()
    db.refresh(user)
    return _serialize_user(db, user)


@router.patch("/rbac/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: UUID,
    payload: UserUpdateRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("manage_users")),
) -> UserOut:
    """Edycja ustawień konta użytkownika: rola, email, hasło, aktywność oraz zakres widoczności hostów/grup/IP."""
    if principal.scope_restricted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Konto z ograniczonym zakresem widoczności nie może modyfikować ustawień ani zakresu kont użytkowników.",
        )

    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono użytkownika.")

    fields = payload.model_fields_set
    new_role_name = user.custom_role_name or user.role
    new_is_active = user.is_active
    new_scope_restricted = bool(user.scope_restricted)

    if "email" in fields and payload.email is not None:
        clean_email = payload.email.strip().lower()
        conflict = db.execute(
            select(User).where(User.email == clean_email, User.id != user_id)
        ).scalar_one_or_none()
        if conflict is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Email '{clean_email}' jest już zajęty.")
        user.email = clean_email

    if "role_name" in fields and payload.role_name is not None:
        clean_role = payload.role_name.strip().lower()
        if db.get(RbacRole, clean_role) is None:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Nieznana rola RBAC: {clean_role}")
        new_role_name = clean_role

    if "is_active" in fields and payload.is_active is not None:
        if principal.user_id == user_id and not payload.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Nie możesz zablokować własnego aktualnie zalogowanego konta.",
            )
        new_is_active = payload.is_active

    if "scope_restricted" in fields and payload.scope_restricted is not None:
        new_scope_restricted = payload.scope_restricted

    # Ochrona ostatniego aktywnego, nieograniczonego administratora
    current_eff_role = user.custom_role_name or user.role
    was_unrestricted_admin = (
        user.is_active
        and not bool(user.scope_restricted)
        and "manage_users" in (resolve_role_permissions(db, current_eff_role) or set())
    )
    will_be_unrestricted_admin = (
        new_is_active
        and not new_scope_restricted
        and "manage_users" in (resolve_role_permissions(db, new_role_name) or set())
    )
    if was_unrestricted_admin and not will_be_unrestricted_admin:
        if _count_other_unrestricted_admins(db, user.id) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="W systemie musi pozostać co najmniej jeden aktywny administrator z pełnym dostępem.",
            )

    if "role_name" in fields and payload.role_name is not None:
        user.role = new_role_name if new_role_name in BUILTIN_ROLE_PERMS_BY_NAME else "read_only"
        user.custom_role_name = new_role_name

    if "is_active" in fields and payload.is_active is not None:
        user.is_active = new_is_active

    if "password" in fields and payload.password:
        user.password_hash = hash_password(payload.password)

    if "scope_restricted" in fields and payload.scope_restricted is not None:
        user.scope_restricted = new_scope_restricted

    if "allowed_scope" in fields and payload.allowed_scope is not None:
        user.allowed_scope = _validate_scope_references(db, payload.allowed_scope)

    record_audit_event(
        db,
        principal,
        action="rbac.user.update",
        resource_type="user",
        resource_id=str(user.id),
        details={
            "username": user.username,
            "fields": sorted(fields),
            "role": user.custom_role_name or user.role,
            "is_active": user.is_active,
            "scope_restricted": bool(user.scope_restricted),
            "allowed_scope": user.allowed_scope,
        },
    )
    db.commit()
    db.refresh(user)
    return _serialize_user(db, user)


@router.delete("/rbac/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: UUID,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("manage_users")),
) -> None:
    if principal.scope_restricted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Konto z ograniczonym zakresem widoczności nie może usuwać użytkowników.",
        )
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono użytkownika.")
    if principal.user_id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nie możesz usunąć własnego aktualnie zalogowanego konta.",
        )
    eff_role = user.custom_role_name or user.role
    is_unrestricted_admin = (
        user.is_active
        and not bool(user.scope_restricted)
        and "manage_users" in (resolve_role_permissions(db, eff_role) or set())
    )
    if is_unrestricted_admin and _count_other_unrestricted_admins(db, user.id) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nie można usunąć ostatniego aktywnego administratora z pełnym dostępem.",
        )
    uname = user.username
    db.delete(user)
    record_audit_event(
        db,
        principal,
        action="rbac.user.delete",
        resource_type="user",
        resource_id=str(user_id),
        details={"username": uname},
    )
    db.commit()


@router.get("/audit-logs", response_model=list[AuditLogOut])
def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("manage_users")),
) -> list[AuditLogOut]:
    stmt = select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit)
    if principal.scope_restricted:
        if principal.user_id is not None:
            stmt = stmt.where(AuditLog.user_id == principal.user_id)
        else:
            return []
    rows = db.execute(stmt).scalars().all()
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
