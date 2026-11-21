import re
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import Principal, require_permission
from app.db.models import CustomSignature
from app.db.session import get_db
from app.services.audit import record_audit_event

router = APIRouter(prefix="/signatures", tags=["signatures"])

SeverityType = Literal["info", "low", "medium", "high", "critical"]
MatchType = Literal["header", "cookie", "favicon_hash", "html_fragment", "path_probe", "footer_version"]
REGEX_MATCH_TYPES = {"header", "html_fragment", "footer_version", "path_probe"}
RE2_UNSUPPORTED_RE = re.compile(r"\(\?[=!<]|\\[1-9]")
NOT_NULL_SIGNATURE_FIELDS = {"severity", "match_type", "pattern", "is_enabled"}


def _validate_signature_fields(
    match_type: str,
    pattern: str,
    probe_path: str | None,
) -> tuple[str, str | None]:
    clean_pattern = (pattern or "").strip()
    if not clean_pattern:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Pole 'pattern' nie może być puste.",
        )
    if len(clean_pattern) > 256:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Wzorzec 'pattern' przekracza maksymalną długość 256 znaków (ochrona przed ReDoS).",
        )

    if match_type in REGEX_MATCH_TYPES:
        if RE2_UNSUPPORTED_RE.search(clean_pattern):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Wzorzec zawiera konstrukcje nieobsługiwane przez silnik RE2 (lookahead/lookbehind lub backreference \\1-\\9).",
            )
        try:
            re.compile(clean_pattern)
        except re.error as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Nieprawidłowe wyrażenie regularne w polu 'pattern': {exc}",
            ) from exc

    clean_probe_path: str | None = probe_path.strip() if probe_path else None
    if match_type == "path_probe":
        if not clean_probe_path:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Sygnatura typu 'path_probe' wymaga podania ścieżki względnej 'probe_path' (np. '/admin').",
            )
        if (
            not clean_probe_path.startswith("/")
            or clean_probe_path.startswith("//")
            or "://" in clean_probe_path
            or any(ch.isspace() for ch in clean_probe_path)
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Pole 'probe_path' musi być bezpieczną ścieżką względną zaczynającą się od pojedynczego '/' (bez zewnętrznych URL).",
            )

    return clean_pattern, clean_probe_path


class SignatureOut(BaseModel):
    id: UUID
    name: str
    description: str | None = None
    severity: SeverityType
    match_type: MatchType
    pattern: str
    probe_path: str | None = None
    expected_status: int | None = None
    is_enabled: bool


class SignatureCreateRequest(BaseModel):
    name: str
    description: str | None = None
    severity: SeverityType = "info"
    match_type: MatchType
    pattern: str
    probe_path: str | None = None
    expected_status: int | None = None
    is_enabled: bool = True


class SignatureUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    severity: SeverityType | None = None
    match_type: MatchType | None = None
    pattern: str | None = None
    probe_path: str | None = None
    expected_status: int | None = None
    is_enabled: bool | None = None


def _to_out(sig: CustomSignature) -> SignatureOut:
    return SignatureOut(
        id=sig.id,
        name=sig.name,
        description=sig.description,
        severity=sig.severity,
        match_type=sig.match_type,
        pattern=sig.pattern,
        probe_path=sig.probe_path,
        expected_status=sig.expected_status,
        is_enabled=sig.is_enabled,
    )


@router.get("", response_model=list[SignatureOut])
def list_signatures(
    only_enabled: bool = False,
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("read")),
) -> list[SignatureOut]:
    stmt = select(CustomSignature).order_by(CustomSignature.name)
    if only_enabled:
        stmt = stmt.where(CustomSignature.is_enabled.is_(True))
    rows = db.execute(stmt).scalars().all()
    return [_to_out(r) for r in rows]


@router.post("", response_model=SignatureOut, status_code=status.HTTP_201_CREATED)
def create_signature(
    payload: SignatureCreateRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("add")),
) -> SignatureOut:
    clean_name = (payload.name or "").strip()
    if not clean_name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Nazwa sygnatury nie może być pusta.",
        )
    existing = db.execute(
        select(CustomSignature).where(CustomSignature.name == clean_name)
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Sygnatura o nazwie '{clean_name}' już istnieje.",
        )

    clean_pattern, clean_probe_path = _validate_signature_fields(
        match_type=payload.match_type,
        pattern=payload.pattern,
        probe_path=payload.probe_path,
    )
    data = payload.model_dump()
    data["name"] = clean_name
    data["pattern"] = clean_pattern
    data["probe_path"] = clean_probe_path

    sig = CustomSignature(**data)
    db.add(sig)
    db.flush()
    record_audit_event(db, principal, action="signature.create", resource_type="custom_signature", resource_id=str(sig.id), details={"name": clean_name, "match_type": sig.match_type})
    db.commit()
    db.refresh(sig)
    return _to_out(sig)


@router.patch("/{signature_id}", response_model=SignatureOut)
def update_signature(
    signature_id: UUID,
    payload: SignatureUpdateRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("modify")),
) -> SignatureOut:
    sig = db.get(CustomSignature, signature_id)
    if sig is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono sygnatury.")

    if "name" in payload.model_fields_set:
        clean_name = (payload.name or "").strip()
        if not clean_name:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Nazwa sygnatury nie może być pusta.",
            )
        conflict = db.execute(
            select(CustomSignature).where(
                CustomSignature.name == clean_name,
                CustomSignature.id != signature_id,
            )
        ).scalar_one_or_none()
        if conflict is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Sygnatura o nazwie '{clean_name}' już istnieje.",
            )
        sig.name = clean_name

    for field in payload.model_fields_set:
        if field == "name":
            continue
        val = getattr(payload, field)
        if field in NOT_NULL_SIGNATURE_FIELDS and val is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Pole '{field}' nie może mieć wartości null.",
            )
        setattr(sig, field, val)

    clean_pattern, clean_probe_path = _validate_signature_fields(
        match_type=sig.match_type,
        pattern=sig.pattern,
        probe_path=sig.probe_path,
    )
    sig.pattern = clean_pattern
    sig.probe_path = clean_probe_path

    record_audit_event(db, principal, action="signature.update", resource_type="custom_signature", resource_id=str(sig.id), details={"fields": sorted(payload.model_fields_set)})
    db.commit()
    db.refresh(sig)
    return _to_out(sig)


@router.delete("/{signature_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_signature(
    signature_id: UUID,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("delete")),
) -> None:
    sig = db.get(CustomSignature, signature_id)
    if sig is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nie znaleziono sygnatury.")
    sig_name = sig.name
    db.delete(sig)
    record_audit_event(db, principal, action="signature.delete", resource_type="custom_signature", resource_id=str(signature_id), details={"name": sig_name})
    db.commit()
