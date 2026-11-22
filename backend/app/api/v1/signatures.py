from datetime import datetime, timezone
import json
import re
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Body, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.crypto import AAD_HTTP_COOKIES, AAD_HTTP_HEADERS, decrypt_json
from app.core.security import Principal, require_permission
from app.db.models import CustomSignature, Host, Service
from app.db.session import get_db
from app.services.audit import record_audit_event
from app.services.queries import fetch_latest_http_fingerprints

router = APIRouter(prefix="/signatures", tags=["signatures"])

SeverityType = Literal["info", "low", "medium", "high", "critical"]
MatchType = Literal["header", "cookie", "favicon_hash", "html_fragment", "path_probe", "footer_version"]
ConflictStrategy = Literal["skip", "overwrite", "error"]

REGEX_MATCH_TYPES = {"header", "html_fragment", "footer_version", "path_probe"}
RE2_UNSUPPORTED_RE = re.compile(r"\(\?[=!<]|\\[1-9]")
FOOTER_RE = re.compile(r"(?is)<footer[^>]*>(.*?)</footer>")
NOT_NULL_SIGNATURE_FIELDS = {"severity", "match_type", "pattern", "is_enabled"}
MAX_IMPORT_BATCH = 500

SEVERITY_ALIASES: dict[str, SeverityType] = {
    "info": "info",
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "med": "medium",
    "high": "high",
    "critical": "critical",
    "crit": "critical",
}

MATCH_TYPE_ALIASES: dict[str, MatchType] = {
    "header": "header",
    "header_match": "header",
    "http_header": "header",
    "cookie": "cookie",
    "cookie_name": "cookie",
    "http_cookie": "cookie",
    "favicon_hash": "favicon_hash",
    "favicon": "favicon_hash",
    "favicon_mmh3": "favicon_hash",
    "mmh3": "favicon_hash",
    "html_fragment": "html_fragment",
    "html": "html_fragment",
    "body": "html_fragment",
    "body_regex": "html_fragment",
    "path_probe": "path_probe",
    "path": "path_probe",
    "endpoint": "path_probe",
    "url_probe": "path_probe",
    "footer_version": "footer_version",
    "footer": "footer_version",
}


def _validate_signature_fields_raw(
    match_type: str,
    pattern: str | None,
    probe_path: str | None,
    expected_status: int | None = None,
) -> tuple[str, str | None, int | None]:
    clean_pattern = (pattern or "").strip()
    if match_type != "path_probe" and not clean_pattern:
        raise ValueError("Pole 'pattern' nie może być puste.")
    if len(clean_pattern) > 256:
        raise ValueError("Wzorzec 'pattern' przekracza maksymalną długość 256 znaków (ochrona przed ReDoS).")

    if match_type in REGEX_MATCH_TYPES and clean_pattern:
        if RE2_UNSUPPORTED_RE.search(clean_pattern):
            raise ValueError(
                "Wzorzec zawiera konstrukcje nieobsługiwane przez silnik RE2 (lookahead/lookbehind lub backreference \\1-\\9)."
            )
        try:
            re.compile(clean_pattern)
        except re.error as exc:
            raise ValueError(f"Nieprawidłowe wyrażenie regularne w polu 'pattern': {exc}") from exc

    clean_probe_path: str | None = probe_path.strip() if probe_path else None
    clean_expected_status: int | None = expected_status

    if match_type == "path_probe":
        if not clean_probe_path:
            raise ValueError("Sygnatura typu 'path_probe' wymaga podania ścieżki względnej 'probe_path' (np. '/admin').")
        if (
            not clean_probe_path.startswith("/")
            or clean_probe_path.startswith("//")
            or "://" in clean_probe_path
            or any(ch.isspace() for ch in clean_probe_path)
        ):
            raise ValueError(
                "Pole 'probe_path' musi być bezpieczną ścieżką względną zaczynającą się od pojedynczego '/' (bez zewnętrznych URL)."
            )
        if clean_expected_status is not None and not (100 <= clean_expected_status <= 599):
            raise ValueError("Pole 'expected_status' musi być poprawnym kodem HTTP z zakresu 100–599.")
    else:
        clean_probe_path = None
        clean_expected_status = None

    return clean_pattern, clean_probe_path, clean_expected_status


def _validate_signature_fields(
    match_type: str,
    pattern: str | None,
    probe_path: str | None,
    expected_status: int | None = None,
) -> tuple[str, str | None, int | None]:
    try:
        return _validate_signature_fields_raw(
            match_type=match_type,
            pattern=pattern,
            probe_path=probe_path,
            expected_status=expected_status,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc


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
    pattern: str = ""
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


class SignatureTestRequest(BaseModel):
    match_type: MatchType
    pattern: str = ""
    probe_path: str | None = None
    expected_status: int | None = None
    sample_headers: str | dict[str, str] | None = None
    sample_cookies: list[str] | str | None = None
    sample_html: str | None = None
    sample_status_code: int | None = Field(default=None, ge=100, le=599)
    sample_favicon_hash: str | None = None
    test_against_db: bool = False


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


def _to_portable_dict(sig: CustomSignature) -> dict[str, Any]:
    return {
        "name": sig.name,
        "description": sig.description,
        "severity": sig.severity,
        "match_type": sig.match_type,
        "pattern": sig.pattern,
        "probe_path": sig.probe_path,
        "expected_status": sig.expected_status,
        "is_enabled": sig.is_enabled,
    }


def _parse_bool(val: Any, default: bool = True) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in ("true", "1", "yes", "t")


def _normalize_imported_signature(raw: Any) -> dict[str, Any]:
    """
    Normalizuje pojedynczy wpis JSON z importu (wspiera zarówno eksport Janus ASI,
    jak i popularne aliasy kluczy: type, header_match, cookie_name, path, status, regex, enabled).
    """
    if not isinstance(raw, dict):
        raise ValueError("Element musi być obiektem JSON.")

    raw_name = raw.get("name") or raw.get("title")
    name = str(raw_name).strip() if raw_name is not None else ""
    if not name:
        raise ValueError("Brak wymaganej nazwy sygnatury ('name').")
    if len(name) > 128:
        raise ValueError("Nazwa sygnatury przekracza 128 znaków.")

    raw_mt = str(raw.get("match_type") or raw.get("type") or "").strip().lower()
    match_type = MATCH_TYPE_ALIASES.get(raw_mt)
    if match_type is None:
        raise ValueError(
            f"Nieobsługiwany typ sygnatury: {raw_mt!r}. "
            f"Dozwolone: header, cookie, favicon_hash, html_fragment, path_probe, footer_version."
        )

    raw_sev = str(raw.get("severity") or raw.get("level") or "info").strip().lower()
    severity = SEVERITY_ALIASES.get(raw_sev)
    if severity is None:
        raise ValueError(f"Nieprawidłowa krytyczność (severity): {raw_sev!r}. Dozwolone: info, low, medium, high, critical.")

    desc_raw = raw.get("description") if "description" in raw else raw.get("desc")
    description = str(desc_raw).strip() if desc_raw is not None and str(desc_raw).strip() else None

    pattern_raw: Any = None
    for key in ("pattern", "regex", "value"):
        if key in raw and raw[key] is not None:
            pattern_raw = raw[key]
            break

    # Wygodny alias: {"match_type": "header", "header_name": "X-Powered-By", "value": "PHP"}
    if match_type == "header" and raw.get("header_name") and "pattern" not in raw and "regex" not in raw:
        h_name = str(raw["header_name"]).strip()
        h_val = str(raw.get("value") or "").strip()
        if h_name:
            esc = lambda s: re.sub(r"([.^$*+?{}\[\]\\|()])", r"\\\1", s)
            escaped_h = esc(h_name)
            pattern_raw = rf"(?i)^{escaped_h}:\s*.*{esc(h_val)}" if h_val else rf"(?i)^{escaped_h}:\s*.+"

    pattern_str = str(pattern_raw) if pattern_raw is not None else ""

    probe_path_raw = raw.get("probe_path") or raw.get("path") or raw.get("endpoint")
    probe_path_str = str(probe_path_raw).strip() if probe_path_raw is not None and str(probe_path_raw).strip() else None

    exp_status_raw: Any = None
    for key in ("expected_status", "status_code", "status"):
        if key in raw and raw[key] is not None and str(raw[key]).strip() != "":
            exp_status_raw = raw[key]
            break

    expected_status_int: int | None = None
    if exp_status_raw is not None:
        try:
            expected_status_int = int(exp_status_raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Nieprawidłowa wartość 'expected_status': {exp_status_raw!r}") from exc

    is_enabled = _parse_bool(raw.get("is_enabled") if "is_enabled" in raw else raw.get("enabled"), default=True)

    clean_pattern, clean_probe_path, clean_expected_status = _validate_signature_fields_raw(
        match_type=match_type,
        pattern=pattern_str,
        probe_path=probe_path_str,
        expected_status=expected_status_int,
    )

    return {
        "name": name,
        "description": description,
        "severity": severity,
        "match_type": match_type,
        "pattern": clean_pattern,
        "probe_path": clean_probe_path,
        "expected_status": clean_expected_status,
        "is_enabled": is_enabled,
    }


def _extract_raw_import_bundle(
    payload: Any,
    default_on_conflict: ConflictStrategy,
    default_dry_run: bool,
) -> tuple[list[Any], ConflictStrategy, bool]:
    eff_conflict: ConflictStrategy = default_on_conflict
    eff_dry_run = default_dry_run

    if isinstance(payload, list):
        raw_items = payload
    elif isinstance(payload, dict):
        if payload.get("on_conflict") in ("skip", "overwrite", "error"):
            eff_conflict = payload["on_conflict"]
        if "dry_run" in payload and payload["dry_run"] is not None:
            eff_dry_run = _parse_bool(payload["dry_run"], default=default_dry_run)

        if isinstance(payload.get("signatures"), list):
            raw_items = payload["signatures"]
        elif isinstance(payload.get("rules"), list):
            raw_items = payload["rules"]
        elif isinstance(payload.get("items"), list):
            raw_items = payload["items"]
        elif any(k in payload for k in ("name", "title", "match_type", "type", "pattern", "regex")):
            raw_items = [payload]
        else:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="JSON musi zawierać tablicę sygnatur, obiekt z polem 'signatures' lub pojedynczą definicję sygnatury.",
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Oczekiwano tablicy lub obiektu JSON z sygnaturami.",
        )

    if not raw_items:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Lista sygnatur do zaimportowania jest pusta.",
        )
    if len(raw_items) > MAX_IMPORT_BATCH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Przekroczono limit pojedynczego importu ({MAX_IMPORT_BATCH} sygnatur).",
        )
    return raw_items, eff_conflict, eff_dry_run


def _execute_signature_import(
    *,
    db: Session,
    principal: Principal,
    raw_items: list[Any],
    on_conflict: ConflictStrategy,
    dry_run: bool,
    source: str,
) -> dict[str, Any]:
    if on_conflict == "overwrite" and not dry_run and "modify" not in principal.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Brak uprawnienia 'modify' wymaganego do nadpisywania istniejących sygnatur dla roli '{principal.role}'.",
        )

    existing_rows = db.execute(select(CustomSignature)).scalars().all()
    existing_by_name = {s.name: s for s in existing_rows}

    seen_in_batch: set[str] = set()
    items_report: list[dict[str, Any]] = []
    created_cnt = 0
    updated_cnt = 0
    skipped_cnt = 0
    error_cnt = 0

    for idx, raw in enumerate(raw_items):
        raw_name_hint = str(raw.get("name") or raw.get("title") or f"#{idx + 1}") if isinstance(raw, dict) else f"#{idx + 1}"
        try:
            norm = _normalize_imported_signature(raw)
        except ValueError as exc:
            error_cnt += 1
            items_report.append(
                {
                    "index": idx,
                    "name": raw_name_hint,
                    "match_type": raw.get("match_type") or raw.get("type") if isinstance(raw, dict) else None,
                    "severity": raw.get("severity") if isinstance(raw, dict) else None,
                    "pattern": raw.get("pattern") if isinstance(raw, dict) else None,
                    "status": "error",
                    "message": str(exc),
                }
            )
            continue

        sig_name = norm["name"]
        if sig_name in seen_in_batch:
            skipped_cnt += 1
            items_report.append(
                {
                    "index": idx,
                    "name": sig_name,
                    "match_type": norm["match_type"],
                    "severity": norm["severity"],
                    "pattern": norm["pattern"],
                    "status": "would_skip" if dry_run else "skipped",
                    "message": "Duplikat nazwy w ramach tego samego importu JSON.",
                }
            )
            continue
        seen_in_batch.add(sig_name)

        existing = existing_by_name.get(sig_name)
        if existing is not None:
            if on_conflict == "skip":
                skipped_cnt += 1
                items_report.append(
                    {
                        "index": idx,
                        "name": sig_name,
                        "match_type": norm["match_type"],
                        "severity": norm["severity"],
                        "pattern": norm["pattern"],
                        "status": "would_skip" if dry_run else "skipped",
                        "message": "Sygnatura o tej nazwie już istnieje (pominięto).",
                    }
                )
            elif on_conflict == "error":
                error_cnt += 1
                items_report.append(
                    {
                        "index": idx,
                        "name": sig_name,
                        "match_type": norm["match_type"],
                        "severity": norm["severity"],
                        "pattern": norm["pattern"],
                        "status": "error",
                        "message": "Konflikt: sygnatura o tej nazwie już istnieje w bazie.",
                    }
                )
            else:
                updated_cnt += 1
                if not dry_run:
                    existing.description = norm["description"]
                    existing.severity = norm["severity"]
                    existing.match_type = norm["match_type"]
                    existing.pattern = norm["pattern"]
                    existing.probe_path = norm["probe_path"]
                    existing.expected_status = norm["expected_status"]
                    existing.is_enabled = norm["is_enabled"]
                items_report.append(
                    {
                        "index": idx,
                        "name": sig_name,
                        "match_type": norm["match_type"],
                        "severity": norm["severity"],
                        "pattern": norm["pattern"],
                        "status": "would_update" if dry_run else "updated",
                        "message": "Zaktualizowano istniejącą sygnaturę." if not dry_run else "Istniejąca sygnatura zostanie nadpisana.",
                    }
                )
        else:
            created_cnt += 1
            if not dry_run:
                new_sig = CustomSignature(**norm)
                db.add(new_sig)
                existing_by_name[sig_name] = new_sig
            items_report.append(
                {
                    "index": idx,
                    "name": sig_name,
                    "match_type": norm["match_type"],
                    "severity": norm["severity"],
                    "pattern": norm["pattern"],
                    "status": "would_create" if dry_run else "created",
                    "message": "Dodano nową sygnaturę." if not dry_run else "Gotowa do dodania.",
                }
            )

    if not dry_run and on_conflict == "error" and error_cnt > 0:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": f"Import zatrzymany w trybie 'error' (wykryto błędów/konfliktów: {error_cnt}). Nic nie zostało zapisane.",
                "summary": {
                    "total": len(raw_items),
                    "created": 0,
                    "updated": 0,
                    "skipped": skipped_cnt,
                    "errors": error_cnt,
                },
                "items": items_report,
            },
        )

    if not dry_run and (created_cnt > 0 or updated_cnt > 0):
        record_audit_event(
            db,
            principal,
            action="signature.import",
            resource_type="custom_signature",
            resource_id=source,
            details={
                "on_conflict": on_conflict,
                "total": len(raw_items),
                "created": created_cnt,
                "updated": updated_cnt,
                "skipped": skipped_cnt,
                "errors": error_cnt,
            },
        )
        db.commit()

    return {
        "dry_run": dry_run,
        "on_conflict": on_conflict,
        "summary": {
            "total": len(raw_items),
            "created": created_cnt,
            "updated": updated_cnt,
            "skipped": skipped_cnt,
            "errors": error_cnt,
        },
        "items": items_report,
    }


def _extract_footer_section(body: str) -> str:
    m = FOOTER_RE.search(body)
    if m:
        return m.group(1)
    if len(body) > 4096:
        return body[-4096:]
    return body


def _parse_sample_headers(raw: str | dict[str, str] | None) -> dict[str, str]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {str(k).strip(): str(v).strip() for k, v in raw.items() if str(k).strip()}
    out: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip()
            if k:
                out[k] = v.strip()
    return out


def _parse_sample_cookies(raw: list[str] | str | None) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(c).strip() for c in raw if str(c).strip()]
    return [part.strip() for part in re.split(r"[,;\n]", raw) if part.strip()]


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


@router.get("/export")
def export_signatures(
    only_enabled: bool = Query(default=False),
    ids: str | None = Query(default=None, description="Opcjonalna lista UUID sygnatur oddzielona przecinkiem"),
    download: bool = Query(default=False),
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("read")),
):
    """Eksportuje wybrane lub wszystkie sygnatury w przenośnym formacie JSON (bez UUID bazy)."""
    stmt = select(CustomSignature).order_by(CustomSignature.name)
    if only_enabled:
        stmt = stmt.where(CustomSignature.is_enabled.is_(True))
    if ids and ids.strip():
        parsed_ids: list[UUID] = []
        for tok in ids.split(","):
            tok = tok.strip()
            if not tok:
                continue
            try:
                parsed_ids.append(UUID(tok))
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Nieprawidłowy UUID na liście 'ids': {tok!r}",
                ) from exc
        if parsed_ids:
            stmt = stmt.where(CustomSignature.id.in_(parsed_ids))

    rows = db.execute(stmt).scalars().all()
    bundle = {
        "schema_version": "1.0",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "count": len(rows),
        "signatures": [_to_portable_dict(r) for r in rows],
    }
    headers = (
        {"Content-Disposition": 'attachment; filename="janus_asi_signatures.json"'}
        if download
        else None
    )
    return JSONResponse(content=bundle, headers=headers)


@router.get("/observed-artifacts")
def get_observed_artifacts(
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("read")),
) -> dict[str, Any]:
    """
    Zwraca unikalne nagłówki HTTP, ciasteczka oraz hashe Favicon MMH3 zaobserwowane dotąd w bazie —
    używane jako podpowiedzi 1-klik w kreatorze sygnatur.
    """
    svc_rows = db.execute(
        select(Service, Host.ip_address)
        .join(Host, Host.id == Service.host_id)
        .where(Service.state == "open", Host.status.notin_(["offline", "archived"]))
        .limit(500)
    ).all()

    svc_ids = [s.id for s, _ in svc_rows]
    latest_fps = fetch_latest_http_fingerprints(db, svc_ids)

    header_counts: dict[str, int] = {}
    cookie_counts: dict[str, int] = {}
    favicon_map: dict[str, set[str]] = {}

    for svc, ip_val in svc_rows:
        fp = latest_fps.get(svc.id)
        if fp is None:
            continue
        ip_str = str(ip_val).split("/")[0]
        endpoint = f"{ip_str}:{svc.port}"

        headers = decrypt_json(fp.headers_encrypted, default={}, associated_data=AAD_HTTP_HEADERS) or {}
        for k in headers.keys():
            ks = str(k).strip()
            if ks:
                header_counts[ks] = header_counts.get(ks, 0) + 1

        cookies = decrypt_json(fp.cookies_encrypted, default=[], associated_data=AAD_HTTP_COOKIES) or []
        for c in cookies:
            cs = str(c).strip()
            if cs:
                cookie_counts[cs] = cookie_counts.get(cs, 0) + 1

        if fp.favicon_mmh3_hash:
            favicon_map.setdefault(str(fp.favicon_mmh3_hash), set()).add(endpoint)

    header_names = [k for k, _ in sorted(header_counts.items(), key=lambda kv: (-kv[1], kv[0].lower()))[:30]]
    cookie_names = [k for k, _ in sorted(cookie_counts.items(), key=lambda kv: (-kv[1], kv[0].lower()))[:30]]
    favicons = [
        {"hash": h, "count": len(eps), "sample_endpoints": sorted(eps)[:5]}
        for h, eps in sorted(favicon_map.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:20]
    ]
    return {
        "header_names": header_names,
        "cookies": cookie_names,
        "favicons": favicons,
    }


@router.post("/import")
def import_signatures_json(
    payload: Any = Body(...),
    on_conflict: ConflictStrategy = Query(default="skip"),
    dry_run: bool = Query(default=False),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("add")),
) -> dict[str, Any]:
    """
    Zbiorczy import sygnatur z wklejonego JSON-a (obsługuje tablicę, obiekt z polem 'signatures' lub pojedynczą regułę).
    Wspiera dry_run=true (podgląd walidacji przed zapisem) oraz tryby konfliktów skip / overwrite / error.
    """
    raw_items, eff_conflict, eff_dry_run = _extract_raw_import_bundle(payload, on_conflict, dry_run)
    return _execute_signature_import(
        db=db,
        principal=principal,
        raw_items=raw_items,
        on_conflict=eff_conflict,
        dry_run=eff_dry_run,
        source="json-body",
    )


@router.post("/import-file")
async def import_signatures_file(
    file: UploadFile = File(...),
    on_conflict: ConflictStrategy = Query(default="skip"),
    dry_run: bool = Query(default=False),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("add")),
) -> dict[str, Any]:
    """Zbiorczy import sygnatur bezpośrednio z przesłanego pliku .json."""
    content = (await file.read()).decode("utf-8-sig", errors="replace").strip()
    if not content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Przesłany plik JSON z sygnaturami jest pusty.")
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Błędny format JSON: {exc}") from exc

    raw_items, eff_conflict, eff_dry_run = _extract_raw_import_bundle(parsed, on_conflict, dry_run)
    return _execute_signature_import(
        db=db,
        principal=principal,
        raw_items=raw_items,
        on_conflict=eff_conflict,
        dry_run=eff_dry_run,
        source=file.filename or "upload.json",
    )


@router.post("/test")
def test_signature(
    payload: SignatureTestRequest,
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("read")),
) -> dict[str, Any]:
    """
    Bezpieczny pasywny tester sygnatury (bez zapytań sieciowych):
      - waliduje wzorzec RE2 i ścieżkę probe_path,
      - dopasowuje do wklejonej próbki (nagłówki / ciasteczka / HTML / kod statusu / hash favicony),
      - opcjonalnie (test_against_db=true) sprawdza trafienia na już zebranych rekordach http_fingerprints w DB.
    """
    clean_pattern, clean_probe_path, clean_expected_status = _validate_signature_fields(
        match_type=payload.match_type,
        pattern=payload.pattern,
        probe_path=payload.probe_path,
        expected_status=payload.expected_status,
    )

    compiled = re.compile(clean_pattern) if (payload.match_type in REGEX_MATCH_TYPES and clean_pattern) else None

    sample_match = False
    sample_evidence: str | None = None
    sample_note: str | None = None

    if payload.match_type == "header":
        hdrs = _parse_sample_headers(payload.sample_headers)
        if not hdrs:
            sample_note = "Podaj przykładowe nagłówki (np. 'X-Powered-By: PHP/7.4.33'), aby sprawdzić próbkę."
        elif compiled:
            for k, v in hdrs.items():
                line = f"{k}: {v}"
                if compiled.search(line[:2048]):
                    sample_match = True
                    sample_evidence = line
                    break
    elif payload.match_type == "cookie":
        cookies = _parse_sample_cookies(payload.sample_cookies)
        if not cookies:
            sample_note = "Podaj nazwy ciasteczek (np. 'PHPSESSID, csrftoken'), aby sprawdzić próbkę."
        else:
            needle = clean_pattern.lower()
            for c in cookies:
                if needle in c.lower():
                    sample_match = True
                    sample_evidence = f"cookie={c}"
                    break
    elif payload.match_type == "favicon_hash":
        sample_fav = (payload.sample_favicon_hash or "").strip()
        if not sample_fav:
            sample_note = "Podaj przykładowy hash Favicon MMH3, aby sprawdzić próbkę."
        elif sample_fav == clean_pattern:
            sample_match = True
            sample_evidence = f"favicon_mmh3={sample_fav}"
    elif payload.match_type == "html_fragment":
        html = payload.sample_html or ""
        if not html:
            sample_note = "Wklej fragment HTML, aby sprawdzić dopasowanie."
        elif compiled:
            m = compiled.search(html[:65536])
            if m:
                sample_match = True
                sample_evidence = m.group(0).strip()[:160]
    elif payload.match_type == "footer_version":
        html = payload.sample_html or ""
        if not html:
            sample_note = "Wklej fragment stopki lub stronę HTML, aby sprawdzić dopasowanie."
        elif compiled:
            footer_txt = _extract_footer_section(html[:65536])
            m = compiled.search(footer_txt)
            if m:
                sample_match = True
                sample_evidence = f"footer: {m.group(0).strip()[:160]}"
    elif payload.match_type == "path_probe":
        html = payload.sample_html or ""
        st = payload.sample_status_code if payload.sample_status_code is not None else (clean_expected_status or 200)
        status_ok = (st == clean_expected_status) if clean_expected_status is not None else (200 <= st < 400)
        if not status_ok:
            sample_note = f"Kod HTTP próbki ({st}) nie zgadza się z oczekiwanym ({clean_expected_status or '2xx/3xx'})."
        elif not clean_pattern:
            sample_match = True
            sample_evidence = f"GET {clean_probe_path} -> HTTP {st} (dopasowanie po statusie + anty-soft-404)"
        elif not html:
            sample_note = "Wklej przykładową treść odpowiedzi dla tej ścieżki, aby sprawdzić wzorzec treści."
        elif compiled and compiled.search(html[:65536]):
            sample_match = True
            sample_evidence = f"GET {clean_probe_path} -> HTTP {st} (len={len(html)})"

    db_test: dict[str, Any] | None = None
    if payload.test_against_db:
        if payload.match_type in ("header", "cookie", "favicon_hash"):
            svc_rows = db.execute(
                select(Service, Host)
                .join(Host, Host.id == Service.host_id)
                .where(Service.state == "open", Host.status.notin_(["offline", "archived"]))
                .limit(500)
            ).all()
            svc_ids = [s.id for s, _ in svc_rows]
            latest_fps = fetch_latest_http_fingerprints(db, svc_ids)

            checked = 0
            db_matches: list[dict[str, Any]] = []
            for svc, host in svc_rows:
                fp = latest_fps.get(svc.id)
                if fp is None:
                    continue
                checked += 1
                evidence: str | None = None
                if payload.match_type == "header" and compiled:
                    hdrs = decrypt_json(fp.headers_encrypted, default={}, associated_data=AAD_HTTP_HEADERS) or {}
                    for k, v in hdrs.items():
                        line = f"{k}: {v}"
                        if compiled.search(line[:2048]):
                            evidence = line
                            break
                elif payload.match_type == "cookie":
                    cookies = decrypt_json(fp.cookies_encrypted, default=[], associated_data=AAD_HTTP_COOKIES) or []
                    needle = clean_pattern.lower()
                    for c in cookies:
                        if needle in str(c).lower():
                            evidence = f"cookie={c}"
                            break
                elif payload.match_type == "favicon_hash":
                    if fp.favicon_mmh3_hash and fp.favicon_mmh3_hash == clean_pattern:
                        evidence = f"favicon_mmh3={fp.favicon_mmh3_hash}"

                if evidence is not None:
                    db_matches.append(
                        {
                            "host_id": str(host.id),
                            "ip_address": str(host.ip_address).split("/")[0],
                            "hostname": host.hostname,
                            "port": svc.port,
                            "protocol": svc.protocol,
                            "url": fp.url,
                            "evidence": evidence,
                        }
                    )
            db_test = {
                "supported": True,
                "note": None,
                "services_checked": checked,
                "matches_count": len(db_matches),
                "matches": db_matches[:50],
            }
        else:
            db_test = {
                "supported": False,
                "note": (
                    f"Typ '{payload.match_type}' wymaga pełnej treści HTML lub pasywnej sondy GET w trakcie skanu "
                    "(baza nie magazynuje całych ciał stron HTML). Użyj pola próbki powyżej lub uruchom skan."
                ),
                "services_checked": 0,
                "matches_count": 0,
                "matches": [],
            }

    return {
        "valid": True,
        "match_type": payload.match_type,
        "pattern": clean_pattern,
        "probe_path": clean_probe_path,
        "expected_status": clean_expected_status,
        "sample_match": sample_match,
        "sample_evidence": sample_evidence,
        "sample_note": sample_note,
        "db_test": db_test,
    }


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
    if len(clean_name) > 128:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Nazwa sygnatury przekracza 128 znaków.",
        )
    existing = db.execute(
        select(CustomSignature).where(CustomSignature.name == clean_name)
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Sygnatura o nazwie '{clean_name}' już istnieje.",
        )

    clean_pattern, clean_probe_path, clean_expected_status = _validate_signature_fields(
        match_type=payload.match_type,
        pattern=payload.pattern,
        probe_path=payload.probe_path,
        expected_status=payload.expected_status,
    )
    data = payload.model_dump()
    data["name"] = clean_name
    data["pattern"] = clean_pattern
    data["probe_path"] = clean_probe_path
    data["expected_status"] = clean_expected_status

    sig = CustomSignature(**data)
    db.add(sig)
    db.flush()
    record_audit_event(
        db,
        principal,
        action="signature.create",
        resource_type="custom_signature",
        resource_id=str(sig.id),
        details={"name": clean_name, "match_type": sig.match_type},
    )
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
        if len(clean_name) > 128:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Nazwa sygnatury przekracza 128 znaków.",
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

    clean_pattern, clean_probe_path, clean_expected_status = _validate_signature_fields(
        match_type=sig.match_type,
        pattern=sig.pattern,
        probe_path=sig.probe_path,
        expected_status=sig.expected_status,
    )
    sig.pattern = clean_pattern
    sig.probe_path = clean_probe_path
    sig.expected_status = clean_expected_status

    record_audit_event(
        db,
        principal,
        action="signature.update",
        resource_type="custom_signature",
        resource_id=str(sig.id),
        details={"fields": sorted(payload.model_fields_set)},
    )
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
    record_audit_event(
        db,
        principal,
        action="signature.delete",
        resource_type="custom_signature",
        resource_id=str(signature_id),
        details={"name": sig_name},
    )
    db.commit()
