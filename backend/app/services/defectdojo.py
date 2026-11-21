"""
Serwis integracji z DefectDojo API v2.
- Buduje raport w formacie Generic Findings Import (JSON) natywnie obsługiwanym przez DefectDojo.
- Automatycznie pomija hosty i usługi oznaczone w asset_overrides jako is_ignored lub is_false_positive.
- Dołącza odszyfrowane notatki (AES-256-GCM), jednostkę właściciela i tagi z asset_overrides.
- Wysyła raport przez POST /api/v2/reimport-scan/ jako multipart/form-data
  (lub zwraca gotowy payload w trybie dry_run=True).
"""

from datetime import datetime, timezone
import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

import httpx
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, selectinload

from app.core.crypto import (
    AAD_INTEGRATION_TOKEN,
    AAD_OVERRIDE_NOTES,
    decrypt_field,
    decrypt_field_safe,
)
from app.db.models import (
    AssetOverride,
    ChangeEvent,
    DefectDojoExport,
    Host,
    HTTPFingerprint,
    Integration,
    Service,
    SignatureMatch,
)
from app.services.queries import fetch_latest_http_fingerprints

DEFECTDOJO_INTEGRATION_NAME = "defectdojo-default"
ASI_TEST_TITLE = "AGH Attack Surface Intelligence"
ASI_SCAN_TYPE = "Generic Findings Import"

_URI_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*$")
_TAG_BAD_CHARS_RE = re.compile(r"[\s,'\"/\\()\[\]{};:]+")
_TAG_MULTI_DASH_RE = re.compile(r"-{2,}")
_BLOCKED_DD_HOSTS = {"postgres", "asi_postgres", "redis", "asi_redis", "backend", "asi_backend", "metadata.google.internal"}


def validate_defectdojo_url(raw_url: str) -> str:
    """Waliduje Base URL DefectDojo (ochrona przed SSRF na metadata chmurowe i usługi wewnętrzne)."""
    cleaned = (raw_url or "").strip().rstrip("/")
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Base URL DefectDojo musi zaczynać się od http:// lub https:// i zawierać poprawny host.")
    host = parsed.hostname.lower()
    if host in _BLOCKED_DD_HOSTS:
        raise ValueError(f"Niedozwolony host docelowy dla integracji DefectDojo: {host!r}")
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_link_local or ip.is_unspecified:
            raise ValueError(f"Niedozwolony adres IP link-local/metadata w Base URL DefectDojo: {host}")
    except ValueError as exc:
        if "Niedozwolony" in str(exc):
            raise
    return cleaned


def _sanitize_dd_tag(raw: str) -> str:
    """
    Sanityzuje tag do formatu akceptowanego przez DefectDojo tag_validator
    (bez spacji, przecinków, cudzysłowów i ukośników).
    """
    cleaned = _TAG_BAD_CHARS_RE.sub("-", str(raw or "").strip().lower())
    cleaned = _TAG_MULTI_DASH_RE.sub("-", cleaned).strip("-")
    return cleaned[:64]


def _build_valid_endpoint(latest_fp: HTTPFingerprint | None, svc: Service, ip_str: str) -> str:
    """Buduje poprawny URI endpointu akceptowany przez DefectDojo (Endpoint.from_uri / LocationData)."""
    if latest_fp and latest_fp.url:
        return latest_fp.url
    host_part = f"[{ip_str}]" if ":" in ip_str else ip_str
    raw_scheme = (svc.service_name or svc.protocol or "tcp").strip().lower().rstrip("?")
    if raw_scheme in ("ssl/http", "https-alt", "http-proxy-ssl"):
        scheme = "https"
    elif "/" in raw_scheme:
        scheme = raw_scheme.split("/")[-1]
    else:
        scheme = raw_scheme
    if not _URI_SCHEME_RE.match(scheme):
        scheme = svc.protocol if _URI_SCHEME_RE.match(svc.protocol or "") else "tcp"
    return f"{scheme}://{host_part}:{svc.port}"

SEVERITY_MAP = {
    "info": "Info",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}


def get_defectdojo_integration(db: Session) -> Integration | None:
    return db.execute(
        select(Integration).where(Integration.name == DEFECTDOJO_INTEGRATION_NAME)
    ).scalar_one_or_none()


def _extract_dd_error_detail(resp: httpx.Response) -> str:
    """Wyciąga czytelny komunikat błędu z odpowiedzi JSON/tekstowej DefectDojo API v2."""
    raw_msg = ""
    try:
        data = resp.json()
        if isinstance(data, dict):
            if "detail" in data:
                raw_msg = str(data["detail"])
            elif "message" in data:
                raw_msg = str(data["message"])
            else:
                raw_msg = json.dumps(data, ensure_ascii=False)
        elif isinstance(data, list):
            raw_msg = "; ".join(str(x) for x in data)
    except Exception:
        raw_msg = (resp.text or "").strip()[:300]

    code = resp.status_code
    if code in (401, 403):
        prefix = f"Błąd autoryzacji DefectDojo (HTTP {code}): nieprawidłowy lub nieaktywny token API v2."
    elif code == 404:
        prefix = (
            "Nie znaleziono zasobu w DefectDojo (HTTP 404): "
            "sprawdź Base URL oraz czy podane Engagement ID istnieje."
        )
    elif code == 400:
        prefix = "Błąd walidacji żądania w DefectDojo (HTTP 400)."
    else:
        prefix = f"DefectDojo zwróciło błąd HTTP {code}."

    return f"{prefix} Szczegóły API: {raw_msg}" if raw_msg else prefix


def test_defectdojo_connection(integration: Integration) -> dict[str, Any]:
    """Testuje połączenie z DefectDojo API v2 (GET /api/v2/engagements/{engagement_id}/)."""
    try:
        base = validate_defectdojo_url(integration.base_url)
    except ValueError as exc:
        return {"ok": False, "status_code": None, "url": integration.base_url, "detail": str(exc)}
    try:
        token = decrypt_field(bytes(integration.api_token_encrypted), associated_data=AAD_INTEGRATION_TOKEN)
    except Exception:
        return {
            "ok": False,
            "status_code": None,
            "url": integration.base_url,
            "detail": "Nie można odszyfrować zapisanego tokena API v2 (niezgodny ENCRYPTION_MASTER_KEY) — zapisz token ponownie.",
        }
    if integration.default_engagement_id:
        url = f"{base}/api/v2/engagements/{integration.default_engagement_id}/"
    else:
        url = f"{base}/api/v2/engagements/?limit=1"

    try:
        with httpx.Client(timeout=10.0, verify=integration.verify_tls) as client:
            resp = client.get(url, headers={"Authorization": f"Token {token}"})
        if resp.status_code == 200:
            eng_name = None
            try:
                body = resp.json()
                if isinstance(body, dict):
                    eng_name = body.get("name")
            except Exception:
                pass
            msg = "Połączenie z DefectDojo API v2 powiodło się."
            if eng_name:
                msg += f" (Engagement: '{eng_name}')"
            return {
                "ok": True,
                "status_code": resp.status_code,
                "url": url,
                "detail": msg,
            }
        return {
            "ok": False,
            "status_code": resp.status_code,
            "url": url,
            "detail": _extract_dd_error_detail(resp),
        }
    except httpx.HTTPError as exc:
        return {
            "ok": False,
            "status_code": None,
            "url": url,
            "detail": f"Błąd sieciowy podczas łączenia z DefectDojo ({url}): {exc}",
        }


def _decrypt_override_info(ov: AssetOverride | None) -> dict[str, Any] | None:
    if ov is None:
        return None
    return {
        "custom_label": ov.custom_label,
        "owner_unit": ov.owner_unit,
        "criticality": ov.criticality,
        "tags": list(ov.tags or []),
        "is_false_positive": ov.is_false_positive,
        "is_ignored": ov.is_ignored,
        "notes": decrypt_field_safe(ov.notes_encrypted, associated_data=AAD_OVERRIDE_NOTES) if ov.notes_encrypted else None,
    }


def _format_override_block(host_ov: dict[str, Any] | None, svc_ov: dict[str, Any] | None) -> tuple[str, list[str]]:
    lines: list[str] = []
    tags: list[str] = ["agh-asi"]
    for label, ov in (("Host", host_ov), ("Usługa", svc_ov)):
        if not ov:
            continue
        if ov.get("custom_label"):
            lines.append(f"- Etykieta ({label}): {ov['custom_label']}")
        if ov.get("owner_unit"):
            lines.append(f"- Jednostka / właściciel ({label}): {ov['owner_unit']}")
        if ov.get("criticality"):
            lines.append(f"- Krytyczność ręczna ({label}): {ov['criticality']}")
        if ov.get("notes"):
            lines.append(f"- Notatka analityka ({label}): {ov['notes']}")
        for t in ov.get("tags", []):
            st = _sanitize_dd_tag(t)
            if st and st not in tags:
                tags.append(st)
    block = "\n".join(lines)
    return (f"\n\n### Kontekst z asset_overrides\n{block}" if block else ""), tags


def build_generic_findings_report(
    db: Session,
    *,
    host_ids: list[UUID] | None = None,
    scan_run_id: UUID | None = None,
    only_interesting: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Buduje raport DefectDojo Generic Findings Import (JSON) z aktualnego stanu zasobów.
    Zwraca (payload_json, statystyki).
    """
    stmt = (
        select(Host)
        .options(
            selectinload(Host.services)
            .selectinload(Service.signature_matches)
            .selectinload(SignatureMatch.signature)
        )
        .order_by(Host.ip_address)
    )
    if host_ids:
        stmt = stmt.where(Host.id.in_(host_ids))

    hosts = db.execute(stmt).scalars().all()

    changes_by_service: dict[UUID, list[ChangeEvent]] = {}
    changes_by_host: dict[UUID, list[ChangeEvent]] = {}
    change_stmt = select(ChangeEvent).order_by(desc(ChangeEvent.detected_at))
    if scan_run_id is not None:
        change_stmt = change_stmt.where(ChangeEvent.scan_run_id == scan_run_id)
    else:
        change_stmt = change_stmt.limit(500)
    recent_changes = db.execute(change_stmt).scalars().all()

    run_host_ids: set[UUID] = set()
    for ch in recent_changes:
        run_host_ids.add(ch.host_id)
        changes_by_host.setdefault(ch.host_id, []).append(ch)
        if ch.service_id:
            changes_by_service.setdefault(ch.service_id, []).append(ch)

    if scan_run_id is not None:
        hosts = [h for h in hosts if (h.last_scan_run_id == scan_run_id or h.id in run_host_ids)]

    all_host_ids = [h.id for h in hosts]
    all_service_ids = [s.id for h in hosts for s in h.services]

    host_ov_map: dict[UUID, dict[str, Any]] = {}
    if all_host_ids:
        for ov in db.execute(
            select(AssetOverride).where(
                AssetOverride.entity_type == "host",
                AssetOverride.entity_id.in_(all_host_ids),
            )
        ).scalars().all():
            dec = _decrypt_override_info(ov)
            if dec:
                host_ov_map[ov.entity_id] = dec

    svc_ov_map: dict[UUID, dict[str, Any]] = {}
    if all_service_ids:
        for ov in db.execute(
            select(AssetOverride).where(
                AssetOverride.entity_type == "service",
                AssetOverride.entity_id.in_(all_service_ids),
            )
        ).scalars().all():
            dec = _decrypt_override_info(ov)
            if dec:
                svc_ov_map[ov.entity_id] = dec

    latest_fp_map = fetch_latest_http_fingerprints(db, all_service_ids)

    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    findings: list[dict[str, Any]] = []
    skipped_ignored_or_fp = 0
    skipped_offline = 0
    exported_host_ids: list[UUID] = []

    for h in hosts:
        if h.status in ("offline", "archived"):
            skipped_offline += 1
            continue
        host_ov = host_ov_map.get(h.id)
        if host_ov and (host_ov["is_ignored"] or host_ov["is_false_positive"]):
            skipped_ignored_or_fp += 1
            continue

        ip_str = str(h.ip_address).split("/")[0]
        host_label = f"{ip_str} ({h.hostname})" if h.hostname else ip_str
        exported_host_ids.append(h.id)

        for svc in sorted(h.services, key=lambda s: (s.port, s.protocol)):
            if svc.state != "open":
                continue

            svc_ov = svc_ov_map.get(svc.id)
            if svc_ov and (svc_ov["is_ignored"] or svc_ov["is_false_positive"]):
                skipped_ignored_or_fp += 1
                continue

            latest_fp = latest_fp_map.get(svc.id)

            endpoint = _build_valid_endpoint(latest_fp, svc, ip_str)
            override_block, base_tags = _format_override_block(host_ov, svc_ov)

            latest_sigs: dict[UUID, SignatureMatch] = {}
            for m in sorted(svc.signature_matches, key=lambda x: x.matched_at, reverse=True):
                if m.signature_id not in latest_sigs and m.signature is not None:
                    latest_sigs[m.signature_id] = m

            svc_changes = changes_by_service.get(svc.id, [])
            is_admin = bool(latest_fp and latest_fp.is_admin_panel)
            is_staging = bool(latest_fp and latest_fp.is_staging_env)
            techs = list(latest_fp.technologies or []) if latest_fp else []

            svc_ident = f"{svc.service_name or ''} {svc.product or ''}".lower()
            is_plaintext_or_unauth_infra = (
                svc.port in (21, 23, 6379, 9200, 11211, 27017)
                or any(k in svc_ident for k in ("ftp", "telnet", "redis", "mongodb", "elasticsearch", "memcached"))
            )
            is_exposed_db_or_broker = (
                svc.port in (3306, 5432, 15432, 5672, 5673, 3389, 445, 5900)
                or any(k in svc_ident for k in ("mysql", "mariadb", "postgresql", "postgres", "amqp", "rabbitmq", "ms-wbt-server", "microsoft-ds", "vnc"))
            )
            is_sensitive_infra = is_plaintext_or_unauth_infra or is_exposed_db_or_broker

            has_interesting = bool(latest_sigs or is_admin or is_staging or svc_changes or is_sensitive_infra)
            if only_interesting and not has_interesting:
                continue

            for sig_id, match in latest_sigs.items():
                sig = match.signature
                sev = SEVERITY_MAP.get((sig.severity or "info").lower(), "Info")
                desc_parts = [
                    f"**Host:** {host_label}",
                    f"**Usługa:** {svc.port}/{svc.protocol} ({svc.service_name or 'unknown'} {svc.product or ''} {svc.version or ''})".strip(),
                    f"**Sygnatura:** {sig.name} (`{sig.match_type}`)",
                    f"**Dowód (evidence):** `{match.matched_evidence or 'n/a'}`",
                ]
                if techs:
                    desc_parts.append(f"**Wykryte technologie:** {', '.join(techs)}")
                if latest_fp and latest_fp.title:
                    desc_parts.append(f"**Tytuł strony:** {latest_fp.title}")
                if latest_fp and latest_fp.favicon_mmh3_hash:
                    desc_parts.append(f"**Favicon MMH3:** `{latest_fp.favicon_mmh3_hash}`")
                if latest_fp and latest_fp.tls_subject:
                    desc_parts.append(
                        f"**TLS:** Subject=`{latest_fp.tls_subject}`, Issuer=`{latest_fp.tls_issuer}`, NotAfter=`{latest_fp.tls_not_after}`"
                    )

                tags = list(base_tags)
                if "signature" not in tags:
                    tags.append("signature")
                for t in techs:
                    tl = _sanitize_dd_tag(t)
                    if tl and tl not in tags:
                        tags.append(tl)

                findings.append(
                    {
                        "title": f"[ASI Signature] {sig.name} on {ip_str}:{svc.port}",
                        "description": "\n".join(desc_parts) + override_block,
                        "severity": sev,
                        "active": True,
                        "verified": False,
                        "endpoints": [endpoint],
                        "tags": tags,
                        "unique_id_from_tool": f"asi-sig-{h.id}-{svc.id}-{sig_id}",
                        "vuln_id_from_tool": f"ASI-SIG-{sig.match_type.upper()}",
                        "date": today_str,
                    }
                )

            if is_admin or is_staging or is_sensitive_infra or not latest_sigs:
                if is_admin or is_plaintext_or_unauth_infra:
                    sev_key = "medium"
                elif is_staging or is_exposed_db_or_broker:
                    sev_key = "low"
                else:
                    sev_key = "info"
                if host_ov and host_ov.get("criticality") in ("medium", "high", "critical") and sev_key == "info":
                    sev_key = "low"
                sev = SEVERITY_MAP[sev_key]

                flags = []
                if is_admin:
                    flags.append("Admin Panel")
                if is_staging:
                    flags.append("Staging/Test Env")
                if is_plaintext_or_unauth_infra:
                    flags.append("Exposed Infrastructure")
                elif is_exposed_db_or_broker:
                    flags.append("Exposed DB/Broker")
                prefix = f"[ASI {' / '.join(flags)}]" if flags else "[ASI Exposed Service]"

                desc_parts = [
                    f"**Host:** {host_label} (status: `{h.status}`)",
                    f"**Usługa:** {svc.port}/{svc.protocol} — {svc.service_name or 'unknown'} {svc.product or ''} {svc.version or ''}".strip(),
                ]
                if latest_fp:
                    lat_str = f", czas odpowiedzi: `{latest_fp.response_time_ms} ms`" if latest_fp.response_time_ms is not None else ""
                    desc_parts.append(f"**HTTP:** `{latest_fp.url}` (HTTP {latest_fp.status_code}, tytuł: `{latest_fp.title or 'brak'}`{lat_str})")
                    if latest_fp.probe_error:
                        desc_parts.append(f"**Błąd sondy HTTP:** `{latest_fp.probe_error}`")
                    if latest_fp.favicon_mmh3_hash:
                        desc_parts.append(f"**Favicon MMH3:** `{latest_fp.favicon_mmh3_hash}`")
                    if latest_fp.tls_subject:
                        desc_parts.append(f"**TLS:** Subject=`{latest_fp.tls_subject}`, Issuer=`{latest_fp.tls_issuer}`, NotAfter=`{latest_fp.tls_not_after}`")
                if techs:
                    desc_parts.append(f"**Technologie:** {', '.join(techs)}")
                if svc_changes:
                    recent_types = ", ".join(sorted({c.change_type for c in svc_changes}))
                    desc_parts.append(f"**Ostatnie zmiany (Diff):** {recent_types}")

                tags = list(base_tags)
                if is_admin and "admin-panel" not in tags:
                    tags.append("admin-panel")
                if is_staging and "staging" not in tags:
                    tags.append("staging")
                if is_sensitive_infra and "exposed-infra" not in tags:
                    tags.append("exposed-infra")
                for t in techs:
                    tl = _sanitize_dd_tag(t)
                    if tl and tl not in tags:
                        tags.append(tl)

                findings.append(
                    {
                        "title": f"{prefix} {ip_str}:{svc.port} ({svc.product or svc.service_name or svc.protocol})",
                        "description": "\n".join(desc_parts) + override_block,
                        "severity": sev,
                        "active": True,
                        "verified": False,
                        "endpoints": [endpoint],
                        "tags": tags,
                        "unique_id_from_tool": f"asi-svc-{h.id}-{svc.id}",
                        "vuln_id_from_tool": "ASI-EXPOSED-SERVICE",
                        "date": today_str,
                    }
                )

    payload = {"findings": findings}
    stats = {
        "hosts_evaluated": len(hosts),
        "hosts_exported": len(exported_host_ids),
        "skipped_ignored_or_fp": skipped_ignored_or_fp,
        "skipped_offline": skipped_offline,
        "total_findings": len(findings),
        "only_interesting": only_interesting,
    }
    return payload, stats


def _find_existing_asi_test_id(
    client: httpx.Client,
    base_url: str,
    token: str,
    engagement_id: int,
) -> int | None:
    """
    Sprawdza w DefectDojo, czy w danym engagement_id istnieje już test
    o tytule 'AGH Attack Surface Intelligence' i typie 'Generic Findings Import'.
    Zwraca test_id lub None.
    """
    resp = client.get(
        f"{base_url}/api/v2/tests/",
        params={"engagement": engagement_id, "title": ASI_TEST_TITLE, "limit": 100},
        headers={"Authorization": f"Token {token}"},
    )
    if resp.status_code != 200:
        return None
    data = resp.json()
    results = data.get("results", []) if isinstance(data, dict) else []
    for item in results:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        if item.get("title") != ASI_TEST_TITLE:
            continue
        type_name = item.get("test_type_name")
        if type_name and type_name != ASI_SCAN_TYPE:
            continue
        return int(item["id"])
    return None


def export_to_defectdojo(
    db: Session,
    *,
    host_ids: list[UUID] | None = None,
    scan_run_id: UUID | None = None,
    only_interesting: bool = False,
    close_old_findings: bool | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Eksportuje wybrane obserwacje do DefectDojo API v2 jako multipart/form-data:
    - Pierwszy eksport w engagement_id -> POST /api/v2/import-scan/ (z engagement + test_title)
    - Kolejne eksporty (deduplikacja) -> POST /api/v2/reimport-scan/ (z test=<test_id>)
    W trybie dry_run=True zwraca gotowy payload bez wysyłki HTTP.
    """
    integration = get_defectdojo_integration(db)
    payload, stats = build_generic_findings_report(
        db,
        host_ids=host_ids,
        scan_run_id=scan_run_id,
        only_interesting=only_interesting,
    )

    # Przy pełnym eksporcie bez zawężania hostów/skanu domyślnie zamykamy stare znaleziska (np. oznaczone później jako FP/ignored)
    effective_close_old = (
        close_old_findings
        if close_old_findings is not None
        else (not host_ids and scan_run_id is None and not only_interesting)
    )
    close_old_str = "true" if effective_close_old else "false"

    eng_str = str(integration.default_engagement_id) if (integration and integration.default_engagement_id) else "1"
    base = integration.base_url.rstrip("/") if integration else "http://host.docker.internal:8080"

    import_form_fields = {
        "scan_type": "Generic Findings Import",
        "engagement": eng_str,
        "test_title": ASI_TEST_TITLE,
        "active": "true",
        "verified": "false",
    }
    reimport_form_fields = {
        "scan_type": "Generic Findings Import",
        "test": "<existing_test_id>",
        "test_title": ASI_TEST_TITLE,
        "active": "true",
        "verified": "false",
        "close_old_findings": close_old_str,
    }

    if dry_run:
        return {
            "dry_run": True,
            "configured": integration is not None,
            "strategy": "auto (GET /api/v2/tests/ -> POST /api/v2/import-scan/ lub POST /api/v2/reimport-scan/)",
            "target_import_url": f"{base}/api/v2/import-scan/",
            "target_reimport_url": f"{base}/api/v2/reimport-scan/",
            "engagement_id": integration.default_engagement_id if integration else None,
            "test_title": ASI_TEST_TITLE,
            "close_old_findings": effective_close_old,
            "import_form_fields": import_form_fields,
            "reimport_form_fields": reimport_form_fields,
            "stats": stats,
            "payload": payload,
        }

    if integration is None or not integration.is_active:
        raise ValueError("Integracja DefectDojo nie jest skonfigurowana lub jest wyłączona.")
    base = validate_defectdojo_url(integration.base_url)
    if not integration.default_engagement_id:
        raise ValueError("Brak skonfigurowanego engagement_id w integracji DefectDojo.")
    if not payload.get("findings"):
        raise ValueError(
            "Brak znalezisk spełniających kryteria eksportu (0 findings) — przerwano wysyłkę do DefectDojo."
        )

    try:
        token = decrypt_field(bytes(integration.api_token_encrypted), associated_data=AAD_INTEGRATION_TOKEN)
    except Exception as exc:
        raise ValueError(
            "Nie można odszyfrować zapisanego tokena API v2 DefectDojo (sprawdź ENCRYPTION_MASTER_KEY i zapisz token ponownie)."
        ) from exc
    json_bytes = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")

    try:
        with httpx.Client(timeout=25.0, verify=integration.verify_tls) as client:
            existing_test_id = _find_existing_asi_test_id(
                client=client,
                base_url=base,
                token=token,
                engagement_id=integration.default_engagement_id,
            )
            if existing_test_id is not None:
                url = f"{base}/api/v2/reimport-scan/"
                mode = "reimport-scan"
                form_fields = {
                    "scan_type": "Generic Findings Import",
                    "test": str(existing_test_id),
                    "test_title": ASI_TEST_TITLE,
                    "active": "true",
                    "verified": "false",
                    "close_old_findings": close_old_str,
                }
            else:
                url = f"{base}/api/v2/import-scan/"
                mode = "import-scan"
                form_fields = import_form_fields

            resp = client.post(
                url,
                headers={"Authorization": f"Token {token}"},
                data=form_fields,
                files={"file": ("asi_findings.json", json_bytes, "application/json")},
            )
    except httpx.HTTPError as exc:
        err_msg = f"Błąd sieciowy podczas wysyłki do DefectDojo ({base}): {exc}"
        db.add(
            DefectDojoExport(
                integration_id=integration.id,
                host_id=host_ids[0] if (host_ids and len(host_ids) == 1) else None,
                status="failed",
                error_message=err_msg,
            )
        )
        db.commit()
        raise RuntimeError(err_msg) from exc

    ok = 200 <= resp.status_code < 300
    if not ok:
        err_detail = _extract_dd_error_detail(resp)
        db.add(
            DefectDojoExport(
                integration_id=integration.id,
                host_id=host_ids[0] if (host_ids and len(host_ids) == 1) else None,
                status="failed",
                error_message=err_detail[:500],
            )
        )
        db.commit()
        raise RuntimeError(err_detail)

    resp_data = (
        resp.json()
        if resp.headers.get("content-type", "").startswith("application/json")
        else resp.text[:500]
    )
    dd_test_id = resp_data.get("test") if isinstance(resp_data, dict) else existing_test_id

    db.add(
        DefectDojoExport(
            integration_id=integration.id,
            host_id=host_ids[0] if (host_ids and len(host_ids) == 1) else None,
            defectdojo_finding_id=int(dd_test_id) if isinstance(dd_test_id, int) else None,
            status="exported",
            error_message=None,
        )
    )
    db.commit()

    return {
        "dry_run": False,
        "exported": True,
        "mode": mode,
        "close_old_findings": effective_close_old,
        "test_id": dd_test_id,
        "status_code": resp.status_code,
        "stats": stats,
        "defectdojo_response": resp_data,
    }
