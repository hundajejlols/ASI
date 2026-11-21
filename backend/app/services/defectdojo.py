"""
Serwis integracji z DefectDojo API v2 w modelu 1 IP = 1 Asset (Product).
- Każde IP trafia do własnego Assetu (Product) w DefectDojo (product_name = adres IP),
  dzięki czemu można niezależnie przydzielać uprawnienia administratorom poszczególnych serwerów (RBAC).
- Organizacja (Product Type) przy tworzeniu nowego Assetu:
    1) jeśli host ma ustawione owner_unit w asset_overrides -> używa owner_unit,
    2) w przeciwnym razie -> domyślna organizacja z konfiguracji integracji (np. 'AGH Attack Surface').
  Dla już istniejących Assetów w DefectDojo pomijamy product_type_name, aby ręczne przeniesienie
  Assetu przez administratora do innej organizacji w DefectDojo nigdy nie powodowało konfliktu 400.
- Automatycznie pomija hosty offline/archived oraz zasoby oznaczone w asset_overrides jako
  is_ignored lub is_false_positive.
- Dołącza odszyfrowane notatki (AES-256-GCM), jednostkę właściciela i tagi z asset_overrides.
- Wysyła raporty per IP przez POST /api/v2/reimport-scan/ z auto_create_context=true
  (automatyczne tworzenie brakującej hierarchii + deduplikacja przy kolejnych eksportach)
  albo zwraca podgląd per Asset w trybie dry_run=True.
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
DEFAULT_PRODUCT_TYPE_NAME = "AGH Attack Surface"
DEFAULT_ENGAGEMENT_NAME = "Janus ASI — Attack Surface"
ASI_TEST_TITLE = "Janus ASI — Attack Surface Intelligence"
ASI_SCAN_TYPE = "Generic Findings Import"

DRY_RUN_PREVIEW_LIMIT = 100
DEFAULT_MAX_EXPORT_ASSETS = 500
PRODUCT_PREFETCH_THRESHOLD = 30

_URI_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*$")
_TAG_BAD_CHARS_RE = re.compile(r"[\s,'\"/\\()\[\]{};:]+")
_TAG_MULTI_DASH_RE = re.compile(r"-{2,}")
_BLOCKED_DD_HOSTS = {
    "postgres",
    "asi_postgres",
    "redis",
    "asi_redis",
    "backend",
    "asi_backend",
    "metadata.google.internal",
}

SEVERITY_MAP = {
    "info": "Info",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}


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
    if code == 401:
        prefix = "Błąd autoryzacji DefectDojo (HTTP 401): nieprawidłowy lub nieaktywny token API v2."
    elif code == 403:
        prefix = (
            "Brak uprawnień w DefectDojo (HTTP 403): token API v2 wymaga uprawnień do tworzenia Assetów (Product) "
            "w docelowej Organizacji (Product Type) oraz importu skanów."
        )
    elif code == 404:
        prefix = "Nie znaleziono zasobu w DefectDojo (HTTP 404): sprawdź Base URL API v2."
    elif code == 400:
        prefix = "Błąd walidacji żądania w DefectDojo (HTTP 400)."
    else:
        prefix = f"DefectDojo zwróciło błąd HTTP {code}."

    return f"{prefix} Szczegóły API: {raw_msg}" if raw_msg else prefix


def test_defectdojo_connection(integration: Integration) -> dict[str, Any]:
    """
    Testuje połączenie z DefectDojo API v2 (GET /api/v2/product_types/)
    i sprawdza, czy domyślna Organizacja (Product Type) już istnieje.
    """
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

    pt_name = (integration.product_type_name or DEFAULT_PRODUCT_TYPE_NAME).strip() or DEFAULT_PRODUCT_TYPE_NAME
    eng_name = (integration.engagement_name or DEFAULT_ENGAGEMENT_NAME).strip() or DEFAULT_ENGAGEMENT_NAME
    url = f"{base}/api/v2/product_types/"

    try:
        with httpx.Client(timeout=10.0, verify=integration.verify_tls) as client:
            resp = client.get(
                url,
                params={"name": pt_name, "limit": 20},
                headers={"Authorization": f"Token {token}"},
            )
        if resp.status_code == 200:
            matched_pt: dict[str, Any] | None = None
            try:
                body = resp.json()
                results = body.get("results", []) if isinstance(body, dict) else []
                for item in results:
                    if isinstance(item, dict) and str(item.get("name", "")).strip().lower() == pt_name.lower():
                        matched_pt = item
                        break
            except Exception:
                matched_pt = None

            if matched_pt:
                msg = (
                    f"Połączenie z DefectDojo API v2 powiodło się. "
                    f"Organizacja (Product Type) '{matched_pt.get('name')}' istnieje (ID: {matched_pt.get('id')}). "
                    f"Tryb eksportu: 1 IP = 1 Asset (Product)."
                )
            else:
                msg = (
                    f"Połączenie z DefectDojo API v2 powiodło się. "
                    f"Organizacja (Product Type) '{pt_name}' jeszcze nie istnieje — zostanie utworzona automatycznie "
                    f"przy pierwszym eksporcie (auto_create_context=true). Tryb eksportu: 1 IP = 1 Asset (Product)."
                )
            return {
                "ok": True,
                "status_code": resp.status_code,
                "url": str(resp.url),
                "product_type_name": pt_name,
                "product_type_exists": matched_pt is not None,
                "product_type_id": matched_pt.get("id") if matched_pt else None,
                "engagement_name": eng_name,
                "detail": msg,
            }
        return {
            "ok": False,
            "status_code": resp.status_code,
            "url": str(resp.url),
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
    tags: list[str] = ["janus-asi"]
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


def _build_asset_description(ip_str: str, hostname: str | None, host_ov: dict[str, Any] | None) -> str:
    lines = [f"Asset (host) zarządzany automatycznie przez Janus ASI — IP: {ip_str}."]
    if hostname:
        lines.append(f"Hostname: {hostname}")
    if host_ov:
        if host_ov.get("custom_label"):
            lines.append(f"Etykieta: {host_ov['custom_label']}")
        if host_ov.get("owner_unit"):
            lines.append(f"Jednostka / właściciel: {host_ov['owner_unit']}")
        if host_ov.get("criticality"):
            lines.append(f"Krytyczność ręczna: {host_ov['criticality']}")
        if host_ov.get("notes"):
            lines.append(f"Notatka analityka: {host_ov['notes']}")
    return "\n".join(lines)


def build_per_host_generic_findings_reports(
    db: Session,
    *,
    host_ids: list[UUID] | None = None,
    scan_run_id: UUID | None = None,
    only_interesting: bool = False,
    default_product_type_name: str = DEFAULT_PRODUCT_TYPE_NAME,
    engagement_name: str = DEFAULT_ENGAGEMENT_NAME,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Buduje osobne raporty DefectDojo Generic Findings Import (JSON) dla każdego hosta (1 IP = 1 Asset).
    Nazwa Assetu (product_name) to czysty adres IP; Organizacja (product_type_name) to owner_unit
    z asset_overrides (jeśli ustawione), a w przeciwnym razie default_product_type_name.
    Zwraca (lista_raportów_per_host, statystyki).
    """
    eff_default_pt = (default_product_type_name or DEFAULT_PRODUCT_TYPE_NAME).strip() or DEFAULT_PRODUCT_TYPE_NAME
    eff_engagement_name = (engagement_name or DEFAULT_ENGAGEMENT_NAME).strip() or DEFAULT_ENGAGEMENT_NAME

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
    change_stmt = select(ChangeEvent).order_by(desc(ChangeEvent.detected_at))
    if scan_run_id is not None:
        change_stmt = change_stmt.where(ChangeEvent.scan_run_id == scan_run_id)
    else:
        change_stmt = change_stmt.limit(500)
    recent_changes = db.execute(change_stmt).scalars().all()

    run_host_ids: set[UUID] = set()
    for ch in recent_changes:
        run_host_ids.add(ch.host_id)
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
    host_reports: list[dict[str, Any]] = []
    skipped_ignored_or_fp = 0
    skipped_offline = 0
    skipped_no_findings = 0
    total_findings = 0

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

        owner_unit_clean = (host_ov.get("owner_unit") or "").strip() if host_ov else ""
        if owner_unit_clean:
            product_type_name = owner_unit_clean[:255]
            product_type_source = "owner_unit"
        else:
            product_type_name = eff_default_pt
            product_type_source = "default"

        host_findings: list[dict[str, Any]] = []
        asset_tags: list[str] = ["janus-asi"]
        if host_ov:
            for t in host_ov.get("tags", []):
                st = _sanitize_dd_tag(t)
                if st and st not in asset_tags:
                    asset_tags.append(st)

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
                or any(
                    k in svc_ident
                    for k in ("mysql", "mariadb", "postgresql", "postgres", "amqp", "rabbitmq", "ms-wbt-server", "microsoft-ds", "vnc")
                )
            )
            is_sensitive_infra = is_plaintext_or_unauth_infra or is_exposed_db_or_broker

            has_interesting = bool(latest_sigs or is_admin or is_staging or svc_changes or is_sensitive_infra)
            if only_interesting and not has_interesting:
                continue

            if is_admin and "admin-panel" not in asset_tags:
                asset_tags.append("admin-panel")
            if is_staging and "staging" not in asset_tags:
                asset_tags.append("staging")
            if is_sensitive_infra and "exposed-infra" not in asset_tags:
                asset_tags.append("exposed-infra")

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

                host_findings.append(
                    {
                        "title": f"[Janus ASI Signature] {sig.name} on {ip_str}:{svc.port}",
                        "description": "\n".join(desc_parts) + override_block,
                        "severity": sev,
                        "active": True,
                        "verified": False,
                        "endpoints": [endpoint],
                        "tags": tags,
                        "unique_id_from_tool": f"janus-asi-sig-{h.id}-{svc.id}-{sig_id}",
                        "vuln_id_from_tool": f"JANUS-ASI-SIG-{sig.match_type.upper()}",
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
                prefix = f"[Janus ASI {' / '.join(flags)}]" if flags else "[Janus ASI Exposed Service]"

                desc_parts = [
                    f"**Host:** {host_label} (status: `{h.status}`)",
                    f"**Usługa:** {svc.port}/{svc.protocol} — {svc.service_name or 'unknown'} {svc.product or ''} {svc.version or ''}".strip(),
                ]
                if latest_fp:
                    lat_str = f", czas odpowiedzi: `{latest_fp.response_time_ms} ms`" if latest_fp.response_time_ms is not None else ""
                    desc_parts.append(
                        f"**HTTP:** `{latest_fp.url}` (HTTP {latest_fp.status_code}, tytuł: `{latest_fp.title or 'brak'}`{lat_str})"
                    )
                    if latest_fp.probe_error:
                        desc_parts.append(f"**Błąd sondy HTTP:** `{latest_fp.probe_error}`")
                    if latest_fp.favicon_mmh3_hash:
                        desc_parts.append(f"**Favicon MMH3:** `{latest_fp.favicon_mmh3_hash}`")
                    if latest_fp.tls_subject:
                        desc_parts.append(
                            f"**TLS:** Subject=`{latest_fp.tls_subject}`, Issuer=`{latest_fp.tls_issuer}`, NotAfter=`{latest_fp.tls_not_after}`"
                        )
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

                host_findings.append(
                    {
                        "title": f"{prefix} {ip_str}:{svc.port} ({svc.product or svc.service_name or svc.protocol})",
                        "description": "\n".join(desc_parts) + override_block,
                        "severity": sev,
                        "active": True,
                        "verified": False,
                        "endpoints": [endpoint],
                        "tags": tags,
                        "unique_id_from_tool": f"janus-asi-svc-{h.id}-{svc.id}",
                        "vuln_id_from_tool": "JANUS-ASI-EXPOSED-SERVICE",
                        "date": today_str,
                    }
                )

        if not host_findings:
            skipped_no_findings += 1
            continue

        total_findings += len(host_findings)
        host_reports.append(
            {
                "host_id": h.id,
                "ip_address": ip_str,
                "hostname": h.hostname,
                "product_name": ip_str,
                "product_type_name": product_type_name,
                "product_type_source": product_type_source,
                "engagement_name": eff_engagement_name,
                "test_title": ASI_TEST_TITLE,
                "asset_description": _build_asset_description(ip_str, h.hostname, host_ov),
                "asset_tags": asset_tags,
                "findings_count": len(host_findings),
                "payload": {"findings": host_findings},
            }
        )

    stats = {
        "hosts_evaluated": len(hosts),
        "assets_to_export": len(host_reports),
        "hosts_exported": len(host_reports),
        "skipped_ignored_or_fp": skipped_ignored_or_fp,
        "skipped_offline": skipped_offline,
        "skipped_no_findings": skipped_no_findings,
        "total_findings": total_findings,
        "only_interesting": only_interesting,
    }
    return host_reports, stats


def _lookup_existing_product_id(
    client: httpx.Client,
    base_url: str,
    token: str,
    product_name: str,
) -> int | None:
    """Sprawdza po dokładnej nazwie, czy Asset (Product) o nazwie = IP już istnieje w DefectDojo."""
    resp = client.get(
        f"{base_url}/api/v2/products/",
        params={"name_exact": product_name, "limit": 5},
        headers={"Authorization": f"Token {token}"},
    )
    if resp.status_code != 200:
        return None
    data = resp.json()
    results = data.get("results", []) if isinstance(data, dict) else []
    target = product_name.strip().lower()
    for item in results:
        if isinstance(item, dict) and item.get("id") and str(item.get("name", "")).strip().lower() == target:
            return int(item["id"])
    return None


def _prefetch_existing_products(
    client: httpx.Client,
    base_url: str,
    token: str,
    max_pages: int = 20,
) -> dict[str, int]:
    """Pobiera mapę {nazwa_produktu_lower: id} z DefectDojo dla większych paczek eksportu."""
    mapping: dict[str, int] = {}
    limit = 500
    offset = 0
    for _ in range(max_pages):
        resp = client.get(
            f"{base_url}/api/v2/products/",
            params={"limit": limit, "offset": offset},
            headers={"Authorization": f"Token {token}"},
        )
        if resp.status_code != 200:
            break
        data = resp.json()
        if not isinstance(data, dict):
            break
        results = data.get("results", []) or []
        for item in results:
            if isinstance(item, dict) and item.get("id") and item.get("name"):
                mapping[str(item["name"]).strip().lower()] = int(item["id"])
        if not data.get("next") or len(results) < limit:
            break
        offset += limit
    return mapping


def _enrich_new_product(
    client: httpx.Client,
    base_url: str,
    token: str,
    product_id: int,
    description: str,
    tags: list[str],
) -> None:
    """Best-effort uzupełnienie opisu i tagów nowo utworzonego Assetu (nigdy nie przerywa eksportu)."""
    try:
        client.patch(
            f"{base_url}/api/v2/products/{product_id}/",
            headers={"Authorization": f"Token {token}"},
            json={"description": description, "tags": tags},
        )
    except Exception:
        pass


def export_to_defectdojo(
    db: Session,
    *,
    host_ids: list[UUID] | None = None,
    scan_run_id: UUID | None = None,
    only_interesting: bool = False,
    close_old_findings: bool | None = None,
    dry_run: bool = False,
    max_assets: int = DEFAULT_MAX_EXPORT_ASSETS,
) -> dict[str, Any]:
    """
    Eksportuje obserwacje do DefectDojo API v2 w modelu 1 IP = 1 Asset (Product):
    - Dla każdego IP wywołuje POST /api/v2/reimport-scan/ z auto_create_context=true,
      product_name=<IP>, engagement_name=<z konfiguracji>, test_title=<ASI_TEST_TITLE>.
    - Jeśli Asset nie istnieje jeszcze w DefectDojo, przekazuje product_type_name
      (owner_unit z asset_overrides lub domyślną organizację z konfiguracji).
    - Jeśli Asset już istnieje, pomija product_type_name, aby nie kolidować z ręcznym
      przypisaniem Assetu do innej organizacji/zespołu administratorów w DefectDojo.
    - W trybie dry_run=True zwraca gotowy podgląd per Asset bez wysyłki HTTP.
    """
    integration = get_defectdojo_integration(db)
    default_pt = (
        (integration.product_type_name or DEFAULT_PRODUCT_TYPE_NAME).strip()
        if integration
        else DEFAULT_PRODUCT_TYPE_NAME
    ) or DEFAULT_PRODUCT_TYPE_NAME
    engagement_name = (
        (integration.engagement_name or DEFAULT_ENGAGEMENT_NAME).strip()
        if integration
        else DEFAULT_ENGAGEMENT_NAME
    ) or DEFAULT_ENGAGEMENT_NAME

    host_reports, stats = build_per_host_generic_findings_reports(
        db,
        host_ids=host_ids,
        scan_run_id=scan_run_id,
        only_interesting=only_interesting,
        default_product_type_name=default_pt,
        engagement_name=engagement_name,
    )

    # Ponieważ każde IP ma własny Asset i Test, close_old_findings działa bezpiecznie w obrębie jednego IP
    effective_close_old = (
        close_old_findings
        if close_old_findings is not None
        else (not only_interesting)
    )
    close_old_str = "true" if effective_close_old else "false"
    base = integration.base_url.rstrip("/") if integration else "http://host.docker.internal:8080"

    if dry_run:
        preview_reports = host_reports[:DRY_RUN_PREVIEW_LIMIT]
        assets_preview = [
            {
                "host_id": str(r["host_id"]),
                "ip_address": r["ip_address"],
                "hostname": r["hostname"],
                "product_name": r["product_name"],
                "product_type_name": r["product_type_name"],
                "product_type_source": r["product_type_source"],
                "engagement_name": r["engagement_name"],
                "test_title": r["test_title"],
                "findings_count": r["findings_count"],
                "form_fields": {
                    "scan_type": ASI_SCAN_TYPE,
                    "product_name": r["product_name"],
                    "product_type_name": r["product_type_name"],
                    "engagement_name": r["engagement_name"],
                    "test_title": r["test_title"],
                    "auto_create_context": "true",
                    "deduplication_on_engagement": "true",
                    "active": "true",
                    "verified": "false",
                    "close_old_findings": close_old_str,
                },
                "payload": r["payload"],
            }
            for r in preview_reports
        ]
        return {
            "dry_run": True,
            "configured": integration is not None,
            "mode": "per_host_asset",
            "strategy": "1 IP = 1 Asset (Product): POST /api/v2/reimport-scan/ z auto_create_context=true (product_type_name z owner_unit lub domyślnej organizacji przy tworzeniu nowego Assetu)",
            "target_reimport_url": f"{base}/api/v2/reimport-scan/",
            "default_product_type_name": default_pt,
            "engagement_name": engagement_name,
            "test_title": ASI_TEST_TITLE,
            "close_old_findings": effective_close_old,
            "stats": stats,
            "assets_preview_truncated": len(host_reports) > DRY_RUN_PREVIEW_LIMIT,
            "assets_preview_limit": DRY_RUN_PREVIEW_LIMIT,
            "assets": assets_preview,
        }

    if integration is None or not integration.is_active:
        raise ValueError("Integracja DefectDojo nie jest skonfigurowana lub jest wyłączona.")
    base = validate_defectdojo_url(integration.base_url)
    if not host_reports:
        raise ValueError(
            "Brak znalezisk spełniających kryteria eksportu (0 Assetów / 0 findings) — przerwano wysyłkę do DefectDojo."
        )
    if max_assets > 0 and len(host_reports) > max_assets:
        raise ValueError(
            f"Wybrano {len(host_reports)} Assetów (IP) do eksportu, co przekracza limit pojedynczego wywołania ({max_assets}). "
            f"Wybierz konkretne hosty (host_ids), zawęź skan (scan_run_id), włącz only_interesting=true lub zwiększ max_assets."
        )

    try:
        token = decrypt_field(bytes(integration.api_token_encrypted), associated_data=AAD_INTEGRATION_TOKEN)
    except Exception as exc:
        raise ValueError(
            "Nie można odszyfrować zapisanego tokena API v2 DefectDojo (sprawdź ENCRYPTION_MASTER_KEY i zapisz token ponownie)."
        ) from exc

    reimport_url = f"{base}/api/v2/reimport-scan/"
    per_host_results: list[dict[str, Any]] = []
    assets_exported = 0
    assets_created = 0
    assets_updated = 0
    assets_failed = 0

    try:
        with httpx.Client(timeout=30.0, verify=integration.verify_tls) as client:
            prefetched_products: dict[str, int] | None = None
            if len(host_reports) > PRODUCT_PREFETCH_THRESHOLD:
                prefetched_products = _prefetch_existing_products(client, base, token)

            for report in host_reports:
                product_name = report["product_name"]
                ip_safe = re.sub(r"[^a-zA-Z0-9._-]", "_", product_name)
                json_bytes = json.dumps(report["payload"], ensure_ascii=False, indent=2).encode("utf-8")

                try:
                    if prefetched_products is not None:
                        existing_product_id = prefetched_products.get(product_name.lower())
                    else:
                        existing_product_id = _lookup_existing_product_id(client, base, token, product_name)

                    form_fields: dict[str, str] = {
                        "scan_type": ASI_SCAN_TYPE,
                        "product_name": product_name,
                        "engagement_name": engagement_name,
                        "test_title": ASI_TEST_TITLE,
                        "auto_create_context": "true",
                        "deduplication_on_engagement": "true",
                        "active": "true",
                        "verified": "false",
                        "close_old_findings": close_old_str,
                    }
                    # Przekazuj product_type_name wyłącznie dla nowych Assetów, aby nie powodować błędu 400
                    # po ręcznym przeniesieniu istniejącego Assetu do innej organizacji w DefectDojo.
                    if existing_product_id is None:
                        form_fields["product_type_name"] = report["product_type_name"]

                    resp = client.post(
                        reimport_url,
                        headers={"Authorization": f"Token {token}"},
                        data=form_fields,
                        files={"file": (f"asi_{ip_safe}_findings.json", json_bytes, "application/json")},
                    )
                except httpx.HTTPError as exc:
                    err_msg = f"Błąd sieciowy podczas wysyłki Assetu {product_name} do DefectDojo ({base}): {exc}"
                    assets_failed += 1
                    db.add(
                        DefectDojoExport(
                            integration_id=integration.id,
                            host_id=report["host_id"],
                            product_name=product_name,
                            status="failed",
                            error_message=err_msg[:500],
                        )
                    )
                    per_host_results.append(
                        {
                            "host_id": str(report["host_id"]),
                            "ip_address": report["ip_address"],
                            "product_name": product_name,
                            "product_type_name": report["product_type_name"],
                            "product_type_source": report["product_type_source"],
                            "findings_count": report["findings_count"],
                            "status": "failed",
                            "error": err_msg,
                        }
                    )
                    continue

                if not (200 <= resp.status_code < 300):
                    err_detail = _extract_dd_error_detail(resp)
                    assets_failed += 1
                    db.add(
                        DefectDojoExport(
                            integration_id=integration.id,
                            host_id=report["host_id"],
                            product_name=product_name,
                            status="failed",
                            error_message=err_detail[:500],
                        )
                    )
                    per_host_results.append(
                        {
                            "host_id": str(report["host_id"]),
                            "ip_address": report["ip_address"],
                            "product_name": product_name,
                            "product_type_name": report["product_type_name"],
                            "product_type_source": report["product_type_source"],
                            "findings_count": report["findings_count"],
                            "status": "failed",
                            "status_code": resp.status_code,
                            "error": err_detail,
                        }
                    )
                    continue

                resp_data = (
                    resp.json()
                    if resp.headers.get("content-type", "").startswith("application/json")
                    else {}
                )
                dd_product_id = resp_data.get("product_id") if isinstance(resp_data, dict) else None
                dd_engagement_id = resp_data.get("engagement_id") if isinstance(resp_data, dict) else None
                dd_test_id = (
                    (resp_data.get("test_id") or resp_data.get("test"))
                    if isinstance(resp_data, dict)
                    else None
                )
                dd_product_type_id = resp_data.get("product_type_id") if isinstance(resp_data, dict) else None

                if existing_product_id is None:
                    action = "created"
                    assets_created += 1
                    if isinstance(dd_product_id, int):
                        _enrich_new_product(
                            client,
                            base,
                            token,
                            dd_product_id,
                            report["asset_description"],
                            report["asset_tags"],
                        )
                        if prefetched_products is not None:
                            prefetched_products[product_name.lower()] = dd_product_id
                else:
                    action = "updated"
                    assets_updated += 1
                    if dd_product_id is None:
                        dd_product_id = existing_product_id

                assets_exported += 1
                db.add(
                    DefectDojoExport(
                        integration_id=integration.id,
                        host_id=report["host_id"],
                        product_name=product_name,
                        defectdojo_product_id=int(dd_product_id) if isinstance(dd_product_id, int) else None,
                        defectdojo_finding_id=int(dd_test_id) if isinstance(dd_test_id, int) else None,
                        status="exported",
                        error_message=None,
                    )
                )
                per_host_results.append(
                    {
                        "host_id": str(report["host_id"]),
                        "ip_address": report["ip_address"],
                        "hostname": report["hostname"],
                        "product_name": product_name,
                        "product_type_name": report["product_type_name"] if existing_product_id is None else None,
                        "product_type_source": report["product_type_source"] if existing_product_id is None else "existing_in_defectdojo",
                        "engagement_name": engagement_name,
                        "action": action,
                        "status": "exported",
                        "status_code": resp.status_code,
                        "product_id": dd_product_id,
                        "product_type_id": dd_product_type_id,
                        "engagement_id": dd_engagement_id,
                        "test_id": dd_test_id,
                        "findings_count": report["findings_count"],
                    }
                )
    finally:
        db.commit()

    if assets_exported == 0 and assets_failed > 0:
        first_err = next((r.get("error") for r in per_host_results if r.get("error")), "Błąd eksportu do DefectDojo.")
        raise RuntimeError(f"Eksport do DefectDojo nie powiódł się dla żadnego z {assets_failed} Assetów. {first_err}")

    final_stats = {
        **stats,
        "assets_exported": assets_exported,
        "assets_created": assets_created,
        "assets_updated": assets_updated,
        "assets_failed": assets_failed,
    }

    return {
        "dry_run": False,
        "exported": assets_exported > 0,
        "partial_failure": assets_failed > 0,
        "mode": "per_host_asset",
        "close_old_findings": effective_close_old,
        "default_product_type_name": default_pt,
        "engagement_name": engagement_name,
        "test_title": ASI_TEST_TITLE,
        "stats": final_stats,
        "results": per_host_results,
    }
