"""
Uwierzytelnianie JWT (HS256) oraz elastyczny RBAC (4 role wbudowane + role własne w tabeli rbac_roles):
  - admin
  - add_delete_modify
  - modify_read
  - read_only
  + dowolne role utworzone przez administratora w POST /api/v1/rbac/roles.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import json
import secrets
import time
from typing import Any
from uuid import UUID

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import RbacRole, User
from app.db.session import get_db


class UserRole(str, Enum):
    ADMIN = "admin"
    ADD_DELETE_MODIFY = "add_delete_modify"
    MODIFY_READ = "modify_read"
    READ_ONLY = "read_only"


ALL_PERMISSIONS: frozenset[str] = frozenset(
    {"read", "modify", "add", "delete", "manage_users", "manage_integrations"}
)

ROLE_PERMISSIONS: dict[UserRole, set[str]] = {
    UserRole.ADMIN: {"read", "modify", "add", "delete", "manage_users", "manage_integrations"},
    UserRole.ADD_DELETE_MODIFY: {"read", "modify", "add", "delete"},
    UserRole.MODIFY_READ: {"read", "modify"},
    UserRole.READ_ONLY: {"read"},
}

BUILTIN_ROLE_PERMS_BY_NAME: dict[str, set[str]] = {r.value: perms for r, perms in ROLE_PERMISSIONS.items()}


@dataclass(frozen=True)
class Principal:
    username: str
    role: str
    permissions: frozenset[str]
    auth_mode: str  # "jwt" | "dev_header"
    user_id: UUID | None = None

    @property
    def value(self) -> str:
        """Zgodność wsteczna z interfejsem Enum.value."""
        return self.role


# --- Haszowanie haseł (scrypt z solą) ---

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)
    return f"scrypt${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        scheme, salt_b64, dk_b64 = stored_hash.split("$", 2)
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


# --- JWT HS256 (stdlib, zero zewnętrznych zależności) ---

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_access_token(
    *,
    user_id: UUID,
    username: str,
    role: str,
    expires_minutes: int | None = None,
) -> str:
    now = int(time.time())
    exp = now + (expires_minutes or settings.jwt_expire_minutes) * 60
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": now,
        "exp": exp,
    }
    h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = hmac.new(settings.jwt_secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Nieprawidłowa struktura tokena JWT.")
        h_b64, p_b64, s_b64 = parts
        header = json.loads(_b64url_decode(h_b64))
        if header.get("alg") != "HS256":
            raise ValueError("Nieobsługiwany algorytm JWT.")
        signing_input = f"{h_b64}.{p_b64}".encode("ascii")
        expected_sig = hmac.new(settings.jwt_secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
        actual_sig = _b64url_decode(s_b64)
        if not hmac.compare_digest(expected_sig, actual_sig):
            raise ValueError("Nieprawidłowy podpis tokena JWT.")
        payload = json.loads(_b64url_decode(p_b64))
        if int(payload.get("exp", 0)) < int(time.time()):
            raise ValueError("Token JWT wygasł.")
        return payload
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("Uszkodzony token JWT.") from exc


def resolve_role_permissions(db: Session | None, role_name: str) -> set[str] | None:
    """Zwraca zbiór uprawnień dla roli (z tabeli rbac_roles lub fallback dla 4 ról wbudowanych)."""
    if db is not None:
        try:
            row = db.execute(select(RbacRole).where(RbacRole.name == role_name)).scalar_one_or_none()
            if row is not None:
                return {str(p) for p in (row.permissions or []) if str(p) in ALL_PERMISSIONS}
        except Exception:
            pass
    if role_name in BUILTIN_ROLE_PERMS_BY_NAME:
        return set(BUILTIN_ROLE_PERMS_BY_NAME[role_name])
    return None


def get_current_principal(
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_dev_role: str | None = Header(default=None, alias="X-Dev-Role"),
    db: Session = Depends(get_db),
) -> Principal:
    """
    Rozpoznaje tożsamość i uprawnienia wywołującego:
    1. Priorytet: `Authorization: Bearer <JWT>` (produkcyjne logowanie użytkowników z tabeli `users`).
    2. Tryb prototypowy (gdy ALLOW_DEV_ROLE_HEADER=true): nagłówek `X-Dev-Role` (w tym dla ról własnych z `rbac_roles`).
    3. Brak obu nagłówków → HTTP 401 Unauthorized (brak anonimowego dostępu do danych skanów!).
    """
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        try:
            claims = decode_access_token(token)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

        uid: UUID | None = None
        try:
            uid = UUID(str(claims.get("sub")))
        except Exception:
            uid = None

        role_name = str(claims.get("role") or "")
        username = str(claims.get("username") or "jwt-user")
        if uid is not None:
            user = db.get(User, uid)
            if user is None or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Konto użytkownika jest nieaktywne lub nie istnieje.",
                )
            username = user.username
            role_name = user.custom_role_name or user.role

        perms = resolve_role_permissions(db, role_name)
        if perms is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Nieznana rola RBAC przypisana do użytkownika: {role_name}",
            )
        return Principal(
            username=username,
            role=role_name,
            permissions=frozenset(perms),
            auth_mode="jwt",
            user_id=uid,
        )

    if settings.allow_dev_role_header and x_dev_role is not None:
        role_clean = x_dev_role.strip()
        perms = resolve_role_permissions(db, role_clean)
        if perms is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Nieznana rola RBAC: {role_clean}",
            )
        return Principal(
            username=f"demo-{role_clean}",
            role=role_clean,
            permissions=frozenset(perms),
            auth_mode="dev_header",
            user_id=None,
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=(
            "Wymagane uwierzytelnienie: podaj nagłówek 'Authorization: Bearer <token>' "
            "(POST /api/v1/auth/login) lub w trybie demo 'X-Dev-Role'."
        ),
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user_role(principal: Principal = Depends(get_current_principal)) -> Principal:
    return principal


def require_permission(permission: str):
    def _checker(principal: Principal = Depends(get_current_principal)) -> Principal:
        if permission not in principal.permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Brak uprawnienia '{permission}' dla roli '{principal.role}'.",
            )
        return principal

    return _checker


def verify_scanner_token(
    x_scanner_token: str | None = Header(default=None, alias="X-Scanner-Token"),
) -> None:
    if not hmac.compare_digest(x_scanner_token or "", settings.scanner_internal_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nieprawidłowy token wewnętrzny skanera.",
        )
