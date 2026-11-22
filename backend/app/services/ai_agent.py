"""
Pasywny AI Security Agent (OpenRouter + deterministyczny silnik CVE/EOL):
  - działa wyłącznie w trybie READ-ONLY (nigdy nie modyfikuje hostów, usług, celów ani nadpisań),
  - po skanie (lub na żądanie) sprawdza wykryte wersje frameworków/serwerów/usług,
  - minimalizuje dane wysyłane do LLM (wysyła wyłącznie wersje, technologie, nazwy sygnatur i metadane TLS;
    nigdy nie wysyła ciasteczek sesyjnych ani wrażliwych nagłówków autoryzacyjnych),
  - ocenia czy host ma bezpieczne wersje, czy trzeba pilnie zaalarmować administratora,
  - zapisuje czytelne alerty w tabeli `ai_alerts` (z pełnym poszanowaniem Asset Scope / ABAC).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
import re
import threading
from typing import Any
from uuid import UUID

import httpx
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, selectinload

from app.core.crypto import (
    AAD_AI_AGENT_KEY,
    AAD_HTTP_HEADERS,
    decrypt_field,
    decrypt_json,
)
from app.db.models import (
    AiAgentConfig,
    AiAlert,
    AssetOverride,
    Host,
    Service,
    SignatureMatch,
)
from app.db.session import SessionLocal
from app.services.queries import fetch_latest_http_fingerprints

logger = logging.getLogger(__name__)

DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_OPENROUTER_MODEL = "google/gemini-2.5-flash"
ALLOWED_URGENCIES = ("critical", "high", "medium", "low", "safe")
URGENCY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "safe": 1}

POPULAR_OPENROUTER_MODELS = [
    {"id": "google/gemini-2.5-flash", "label": "Gemini 2.5 Flash (szybki, polecany)"},
    {"id": "openai/gpt-4o-mini", "label": "OpenAI GPT-4o mini"},
    {"id": "anthropic/claude-3.5-haiku", "label": "Claude 3.5 Haiku"},
    {"id": "meta-llama/llama-3.3-70b-instruct", "label": "Llama 3.3 70B Instruct"},
    {"id": "deepseek/deepseek-chat-v3-0324", "label": "DeepSeek V3"},
]

VERSION_TOKEN_RE = re.compile(r"(\d+(?:\.\d+){1,3})")
HEADER_PROD_VER_RE = re.compile(r"([A-Za-z][A-Za-z0-9._-]{1,32})[/\s]+v?(\d+(?:\.\d+){1,3})")
TEST_WORKER_PREFIXES = ("worker-test", "worker-scope-test", "pytest")


def _parse_ver(ver_str: str | None) -> tuple[int, ...] | None:
    if not ver_str:
        return None
    m = VERSION_TOKEN_RE.search(str(ver_str))
    if not m:
        return None
    parts = [int(p) for p in m.group(1).split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def get_ai_agent_config(db: Session) -> AiAgentConfig | None:
    return db.get(AiAgentConfig, "default")


def _decrypt_api_key(cfg: AiAgentConfig) -> str:
    return decrypt_field(bytes(cfg.api_key_encrypted), associated_data=AAD_AI_AGENT_KEY)


def test_openrouter_connection(cfg: AiAgentConfig) -> dict[str, Any]:
    """Sprawdza poprawność klucza OpenRouter bez zużywania tokenów (GET /api/v1/auth/key)."""
    try:
        api_key = _decrypt_api_key(cfg)
    except Exception as exc:
        return {"ok": False, "error": f"Nie można odszyfrować klucza API: {exc}"}

    base = (cfg.base_url or DEFAULT_OPENROUTER_BASE_URL).rstrip("/")
    url = f"{base}/auth/key"
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(
                url,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "HTTP-Referer": "https://janus-asi.local",
                    "X-Title": "Janus ASI Security Agent",
                },
            )
        if resp.status_code == 200:
            data = resp.json().get("data") if isinstance(resp.json(), dict) else {}
            return {
                "ok": True,
                "status_code": 200,
                "model_name": cfg.model_name,
                "label": data.get("label") if isinstance(data, dict) else None,
                "is_free_tier": data.get("is_free_tier") if isinstance(data, dict) else None,
            }
        return {
            "ok": False,
            "status_code": resp.status_code,
            "error": f"OpenRouter zwrócił HTTP {resp.status_code}: {resp.text[:200]}",
        }
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"Błąd połączenia z OpenRouter: {exc}"}


def _extract_host_telemetry(
    host: Host,
    latest_fp_map: dict[UUID, Any],
    host_override: AssetOverride | None,
) -> dict[str, Any]:
    """
    Buduje zminimalizowany, bezpieczny pakiet telemetrii hosta (bez ciasteczek i nagłówków sesyjnych)
    na potrzeby analizy CVE/EOL oraz modelu LLM.
    """
    ip_str = str(host.ip_address).split("/")[0]
    open_services = [s for s in host.services if s.state == "open"] if host.status not in ("offline", "archived") else []

    detected_stack: list[dict[str, Any]] = []
    seen_stack_keys: set[tuple[str, str, int]] = set()
    services_brief: list[dict[str, Any]] = []
    signatures_brief: list[dict[str, Any]] = []
    tls_issues: list[str] = []
    exposure_flags: list[str] = []

    def _add_stack(name: str, version: str | None, port: int, source: str) -> None:
        clean_name = name.strip()
        clean_ver = (version or "").strip()
        if not clean_name:
            return
        key = (clean_name.lower(), clean_ver.lower(), port)
        if key in seen_stack_keys:
            return
        seen_stack_keys.add(key)
        detected_stack.append(
            {"name": clean_name, "version": clean_ver or None, "port": port, "source": source}
        )

    now = datetime.now(timezone.utc)

    for svc in sorted(open_services, key=lambda s: (s.port, s.protocol)):
        fp = latest_fp_map.get(svc.id)
        if svc.product:
            _add_stack(svc.product, svc.version, svc.port, "nmap")
        elif svc.service_name and svc.version:
            _add_stack(svc.service_name, svc.version, svc.port, "nmap")

        svc_entry: dict[str, Any] = {
            "port": svc.port,
            "protocol": svc.protocol,
            "service": svc.service_name,
            "product": svc.product,
            "version": svc.version,
        }

        if fp is not None:
            hdrs = decrypt_json(fp.headers_encrypted, default={}, associated_data=AAD_HTTP_HEADERS) or {}
            safe_headers: dict[str, str] = {}
            for hk, hv in hdrs.items():
                hkl = str(hk).strip().lower()
                if hkl in ("server", "x-powered-by", "x-generator", "x-aspnet-version", "x-drupal-cache"):
                    val_s = str(hv).strip()[:160]
                    safe_headers[str(hk).strip()] = val_s
                    for m in HEADER_PROD_VER_RE.finditer(val_s):
                        _add_stack(m.group(1), m.group(2), svc.port, f"header:{hk}")

            techs = [str(t).strip() for t in (fp.technologies or []) if str(t).strip()]
            for t in techs:
                m = HEADER_PROD_VER_RE.search(t)
                if m:
                    _add_stack(m.group(1), m.group(2), svc.port, "fingerprint")
                else:
                    _add_stack(t, None, svc.port, "fingerprint")

            svc_entry["http"] = {
                "scheme": fp.scheme,
                "status_code": fp.status_code,
                "title": (fp.title or "")[:120] or None,
                "technologies": techs,
                "safe_headers": safe_headers,
                "is_admin_panel": bool(fp.is_admin_panel),
                "is_staging_env": bool(fp.is_staging_env),
            }

            if fp.is_admin_panel:
                exposure_flags.append(f"Panel administracyjny wystawiony na porcie {svc.port} ({fp.scheme})")
                if fp.scheme == "http":
                    exposure_flags.append(f"Panel administracyjny na nieszyfrowanym HTTP (port {svc.port})")
            if fp.is_staging_env:
                exposure_flags.append(f"Wystawione środowisko STAGING/DEV na porcie {svc.port}")

            if fp.tls_subject and fp.tls_issuer and fp.tls_subject == fp.tls_issuer:
                tls_issues.append(f"Port {svc.port}: certyfikat TLS self-signed ({fp.tls_subject[:80]})")
            if fp.tls_not_after:
                not_after = fp.tls_not_after
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)
                if not_after < now:
                    tls_issues.append(f"Port {svc.port}: wygasły certyfikat TLS (wygasł {not_after.date().isoformat()})")
                elif not_after < now + timedelta(days=14):
                    tls_issues.append(f"Port {svc.port}: certyfikat TLS wygasa wkrótce ({not_after.date().isoformat()})")

        for m in svc.signature_matches:
            if m.signature and m.signature.is_enabled:
                signatures_brief.append(
                    {
                        "port": svc.port,
                        "name": m.signature.name,
                        "severity": m.signature.severity,
                        "evidence": (m.matched_evidence or "")[:160],
                    }
                )
                # Spróbuj wyłuskać wersję również z dopasowania sygnatury (np. meta generator WordPress 4.7)
                if m.matched_evidence:
                    for vm in HEADER_PROD_VER_RE.finditer(m.matched_evidence):
                        _add_stack(vm.group(1), vm.group(2), svc.port, f"signature:{m.signature.name}")

        services_brief.append(svc_entry)

    return {
        "host_id": str(host.id),
        "ip_address": ip_str,
        "hostname": host.hostname,
        "status": host.status,
        "owner_unit": host_override.owner_unit if host_override else None,
        "custom_label": host_override.custom_label if host_override else None,
        "criticality": host_override.criticality if host_override else None,
        "detected_stack": detected_stack,
        "services": services_brief,
        "signatures": signatures_brief,
        "tls_issues": tls_issues,
        "exposure_flags": exposure_flags,
    }


def run_deterministic_cve_check(telemetry: dict[str, Any]) -> dict[str, Any]:
    """
    Deterministyczny pre-check realnych CVE / EOL / krytycznych ekspozycji (0 halucynacji).
    Służy zarówno jako uziemienie faktów dla modelu LLM (OpenRouter), jak i bezpieczny fallback offline.
    """
    findings: list[dict[str, Any]] = []
    cves_set: set[str] = set()
    max_urgency = "safe"

    def _bump(urg: str) -> None:
        nonlocal max_urgency
        if URGENCY_RANK.get(urg, 1) > URGENCY_RANK.get(max_urgency, 1):
            max_urgency = urg

    def _add_finding(
        *,
        name: str,
        version: str | None,
        port: int | None,
        status_label: str,
        urgency: str,
        cves: list[str],
        reason: str,
        remediation: str,
    ) -> None:
        _bump(urgency)
        for c in cves:
            cves_set.add(c)
        findings.append(
            {
                "name": name,
                "version": version,
                "port": port,
                "status": status_label,
                "urgency": urgency,
                "cves": cves,
                "reason": reason,
                "remediation": remediation,
            }
        )

    for item in telemetry.get("detected_stack", []):
        name = str(item.get("name") or "")
        nl = name.lower()
        ver_raw = item.get("version")
        ver = _parse_ver(ver_raw)
        port = item.get("port")

        # 1. PHP
        if nl == "php" or nl.startswith("php"):
            if ver is not None and ver < (8, 1, 0):
                _add_finding(
                    name="PHP",
                    version=ver_raw,
                    port=port,
                    status_label="eol",
                    urgency="critical",
                    cves=["CVE-2024-4577", "CVE-2023-3824"],
                    reason=f"PHP {ver_raw} jest poza wsparciem bezpieczeństwa (EOL) i zawiera znane podatności zdalnego wykonania kodu / błędów pamięci.",
                    remediation="Pilna aktualizacja PHP do wspieranej gałęzi 8.3/8.4 oraz ukrycie nagłówka X-Powered-By (expose_php = Off).",
                )
            elif ver is not None and (
                ((8, 1, 0) <= ver < (8, 1, 29))
                or ((8, 2, 0) <= ver < (8, 2, 20))
                or ((8, 3, 0) <= ver < (8, 3, 8))
            ):
                _add_finding(
                    name="PHP",
                    version=ver_raw,
                    port=port,
                    status_label="vulnerable",
                    urgency="critical",
                    cves=["CVE-2024-4577"],
                    reason=f"PHP {ver_raw} mieści się w zakresie podatnym na CVE-2024-4577 (CGI Argument Injection / RCE) oraz błędy bezpieczeństwa naprawione w nowszych wydaniach.",
                    remediation="Zaktualizuj PHP do najnowszej wersji poprawkowej (>= 8.3.8 / 8.2.20 / 8.1.29) i wyłącz expose_php.",
                )

        # 2. WordPress
        elif "wordpress" in nl:
            if ver is not None and ver < (5, 0, 0):
                cves_wp = ["CVE-2017-1001000"] if (4, 7, 0) <= ver <= (4, 7, 1) else ["CVE-2022-21661"]
                _add_finding(
                    name="WordPress",
                    version=ver_raw,
                    port=port,
                    status_label="vulnerable",
                    urgency="critical",
                    cves=cves_wp,
                    reason=f"WordPress {ver_raw} to silnie przestarzała, podatna gałąź CMS (krytyczne podatności REST API / SQLi / XSS).",
                    remediation="Natychmiastowa aktualizacja rdzenia WordPress do najnowszej wersji 6.x wraz z wtyczkami i motywami oraz ograniczenie dostępu do /wp-login.php.",
                )
            elif ver is not None and ver < (6, 5, 0):
                _add_finding(
                    name="WordPress",
                    version=ver_raw,
                    port=port,
                    status_label="vulnerable",
                    urgency="high",
                    cves=[],
                    reason=f"WordPress {ver_raw} jest starszą wersją wymagającą aktualizacji bezpieczeństwa.",
                    remediation="Zaktualizuj WordPress oraz zainstalowane wtyczki do najnowszej wspieranej wersji 6.x.",
                )

        # 3. Apache HTTP Server
        elif "apache" in nl or nl == "httpd":
            if ver is not None and ver in ((2, 4, 49), (2, 4, 50)):
                _add_finding(
                    name="Apache httpd",
                    version=ver_raw,
                    port=port,
                    status_label="vulnerable",
                    urgency="critical",
                    cves=["CVE-2021-41773", "CVE-2021-42013"],
                    reason=f"Apache HTTP Server {ver_raw} jest podatny na krytyczny Path Traversal i RCE (CISA KEV).",
                    remediation="Natychmiastowa aktualizacja Apache httpd do >= 2.4.62 oraz ustawienie ServerTokens Prod.",
                )
            elif ver is not None and ver < (2, 4, 59):
                _add_finding(
                    name="Apache httpd",
                    version=ver_raw,
                    port=port,
                    status_label="vulnerable",
                    urgency="high",
                    cves=["CVE-2024-38476"],
                    reason=f"Apache HTTP Server {ver_raw} wymaga aktualizacji bezpieczeństwa (podatności proxy/mod_rewrite).",
                    remediation="Zaktualizuj Apache httpd do najnowszej wersji 2.4.x oraz ukryj numer wersji (ServerTokens Prod).",
                )

        # 4. nginx
        elif "nginx" in nl:
            if ver is not None and ver < (1, 24, 0):
                _add_finding(
                    name="nginx",
                    version=ver_raw,
                    port=port,
                    status_label="vulnerable",
                    urgency="high",
                    cves=["CVE-2022-41741", "CVE-2024-7347"],
                    reason=f"nginx {ver_raw} jest starszym wydaniem zawierającym załatane już podatności (m.in. HTTP/2, mp4 module).",
                    remediation="Zaktualizuj nginx do bieżącej gałęzi stable (>= 1.26.x) i wyłącz ujawnianie wersji (server_tokens off;).",
                )
            elif ver is not None and ver < (1, 26, 0):
                _add_finding(
                    name="nginx",
                    version=ver_raw,
                    port=port,
                    status_label="outdated",
                    urgency="medium",
                    cves=["CVE-2024-7347"],
                    reason=f"nginx {ver_raw} jest poprzednią gałęzią stable i ujawnia dokładną wersję serwera.",
                    remediation="Zaplanuj aktualizację nginx do >= 1.26.x i ustaw server_tokens off.",
                )

        # 5. OpenSSH
        elif "openssh" in nl:
            if ver is not None and (8, 5, 0) <= ver < (9, 8, 0):
                _add_finding(
                    name="OpenSSH",
                    version=ver_raw,
                    port=port,
                    status_label="vulnerable",
                    urgency="critical",
                    cves=["CVE-2024-6387"],
                    reason=f"OpenSSH {ver_raw} mieści się w zakresie podatnym na regreSSHion (CVE-2024-6387 — nieautoryzowane RCE na systemach glibc).",
                    remediation="Pilnie zaktualizuj OpenSSH do >= 9.8p1 (lub zweryfikuj backport dystrybucji) i ogranicz dostęp do portu 22 listą ACL/VPN.",
                )
            elif ver is not None and ver < (8, 5, 0):
                _add_finding(
                    name="OpenSSH",
                    version=ver_raw,
                    port=port,
                    status_label="eol",
                    urgency="high",
                    cves=["CVE-2023-38408"],
                    reason=f"OpenSSH {ver_raw} to przestarzała wersja demona SSH.",
                    remediation="Zaktualizuj pakiet openssh-server do wspieranej wersji i ogranicz dostęp sieciowy do SSH.",
                )

        # 6. LegacyCMS / phpMyAdmin / Adminer / Traefik
        elif "legacycms" in nl:
            _add_finding(
                name="LegacyCMS",
                version=ver_raw,
                port=port,
                status_label="eol",
                urgency="high",
                cves=[],
                reason=f"Wykryto przestarzały system CMS ({name} {ver_raw or ''}).".strip(),
                remediation="Zidentyfikuj właściciela aplikacji, wycofaj lub odizoluj przestarzały CMS za VPN/WAF.",
            )
        elif "phpmyadmin" in nl or "adminer" in nl:
            _add_finding(
                name=name,
                version=ver_raw,
                port=port,
                status_label="misconfig",
                urgency="high",
                cves=[],
                reason=f"Panel zarządzania bazą danych ({name}) jest bezpośrednio dostępny z sieci.",
                remediation="Natychmiast ogranicz dostęp do panelu bazodanowego wyłącznie do sieci zarządzającej / VPN.",
            )
        elif "traefik" in nl:
            # Jeśli wykryto otwarty dashboard Traefika
            has_dash_sig = any("traefik" in s.get("name", "").lower() for s in telemetry.get("signatures", []))
            if has_dash_sig:
                _add_finding(
                    name="Traefik Dashboard",
                    version=ver_raw,
                    port=port,
                    status_label="misconfig",
                    urgency="high",
                    cves=[],
                    reason="Niezabezpieczony panel Traefik Dashboard (/dashboard/) ujawnia topologię usług i reguły routingu.",
                    remediation="Wyłącz publiczny api.insecure=true i zabezpiecz dashboard uwierzytelnianiem lub VPN.",
                )

    # Ekspozycje i sygnatury wysokiego ryzyka
    for flag in telemetry.get("exposure_flags", []):
        if "nieszyfrowanym HTTP" in flag:
            _add_finding(
                name="Admin Panel (HTTP)",
                version=None,
                port=None,
                status_label="misconfig",
                urgency="high",
                cves=[],
                reason=flag,
                remediation="Wymuś HTTPS (TLS 1.2/1.3) oraz ogranicz dostęp do panelu administracyjnego do sieci VPN/admin.",
            )
        elif "STAGING/DEV" in flag:
            _add_finding(
                name="Staging / Dev Environment",
                version=None,
                port=None,
                status_label="misconfig",
                urgency="medium",
                cves=[],
                reason=flag,
                remediation="Odizoluj środowisko testowe/staging od sieci ogólnej lub włącz uwierzytelnianie na poziomie reverse proxy.",
            )

    for tls_msg in telemetry.get("tls_issues", []):
        urg = "high" if "wygasły" in tls_msg else "medium"
        _add_finding(
            name="TLS Certificate",
            version=None,
            port=None,
            status_label="misconfig",
            urgency=urg,
            cves=[],
            reason=tls_msg,
            remediation="Odnów lub wymień certyfikat TLS na ważny certyfikat podpisany przez zaufane CA (np. GEANT/TCS dla AGH).",
        )

    for sig in telemetry.get("signatures", []):
        sev = str(sig.get("severity") or "info").lower()
        if sev in ("critical", "high"):
            _add_finding(
                name=sig["name"],
                version=None,
                port=sig.get("port"),
                status_label="misconfig",
                urgency=sev,
                cves=[],
                reason=f"Dopasowano sygnaturę wysokiego ryzyka: {sig['name']} ({sig.get('evidence') or 'wykryto'}).",
                remediation="Zweryfikuj konfigurację usługi i usuń nadmiarową ekspozycję.",
            )

    requires_alert = max_urgency in ("critical", "high")
    ip = telemetry["ip_address"]
    owner = telemetry.get("owner_unit") or "administratora hosta"

    if findings:
        top_names = ", ".join(
            f"{f['name']} {f['version']}".strip() if f.get("version") else f["name"]
            for f in findings[:3]
        )
        title = (
            f"PILNY ALERT: {top_names} na {ip}"
            if requires_alert
            else f"Zalecany przegląd: {top_names} na {ip}"
        )
        summary = " ".join(f["reason"] for f in findings[:3])
        remediation = " ".join(dict.fromkeys(f["remediation"] for f in findings[:3]))
        cve_line = f" Powiązane CVE: {', '.join(sorted(cves_set))}." if cves_set else ""
        admin_msg = (
            f"[{max_urgency.upper()}] Host {ip} ({telemetry.get('hostname') or 'brak DNS'}): "
            f"wykryto {top_names}.{cve_line} Zalecana pilna weryfikacja przez {owner}. {remediation}"
        )
    else:
        stack_desc = ", ".join(
            f"{s['name']}{' ' + s['version'] if s.get('version') else ''}"
            for s in telemetry.get("detected_stack", [])[:4]
        )
        title = f"Host {ip} — brak znanych podatnych wersji"
        summary = (
            f"Przeanalizowano wykryte usługi ({stack_desc or 'brak jawnych wersji oprogramowania'}). "
            f"Nie znaleziono znanych krytycznych wersji podatnych ani przestarzałych gałęzi EOL."
        )
        remediation = "Utrzymuj bieżące aktualizacje bezpieczeństwa i regularne skany cykliczne."
        admin_msg = ""

    return {
        "urgency": max_urgency,
        "requires_admin_alert": requires_alert,
        "title": title[:250],
        "affected_software": [
            {
                "name": f["name"],
                "version": f.get("version"),
                "port": f.get("port"),
                "status": f["status"],
                "cves": f["cves"],
                "reason": f["reason"],
            }
            for f in findings
        ],
        "cves": sorted(cves_set),
        "summary": summary,
        "admin_alert_message": admin_msg or None,
        "remediation": remediation,
    }


def _extract_json_object(raw_text: str) -> dict[str, Any]:
    text_s = (raw_text or "").strip()
    if text_s.startswith("```"):
        text_s = re.sub(r"^```(?:json)?\s*", "", text_s)
        text_s = re.sub(r"\s*```$", "", text_s)
    try:
        parsed = json.loads(text_s)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    start = text_s.find("{")
    end = text_s.rfind("}")
    if start != -1 and end > start:
        parsed = json.loads(text_s[start : end + 1])
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("Model AI nie zwrócił poprawnego obiektu JSON.")


def _call_openrouter_for_host(
    cfg: AiAgentConfig,
    telemetry: dict[str, Any],
    precheck: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    """Wywołuje OpenRouter Chat Completions z ustrukturyzowaną telemetrią hosta."""
    api_key = _decrypt_api_key(cfg)
    base = (cfg.base_url or DEFAULT_OPENROUTER_BASE_URL).rstrip("/")
    url = f"{base}/chat/completions"

    system_prompt = (
        "Jesteś pasywnym agentem bezpieczeństwa (READ-ONLY) systemu Janus ASI w Centrum Bezpieczeństwa Informatycznego AGH. "
        "Twoim JEDYNYM zadaniem jest ocena wyników pasywnego skanu hosta: sprawdzenie czy wykryte wersje frameworków, CMS, "
        "serwerów HTTP, SSH i certyfikatów TLS są bezpieczne, czy podatne/przestarzałe (EOL/CVE) i czy trzeba PILNIE "
        "zaalarmować administratora. NICZEGO nie modyfikujesz.\n"
        "ZASADY:\n"
        "1. Odpowiadaj WYŁĄCZNIE poprawnym obiektem JSON (bez markdownu) po polsku.\n"
        "2. Nie wymyślaj nieistniejących numerów CVE. Uwzględnij zweryfikowane trafienia z pola `deterministic_precheck` "
        "oraz swoją realną wiedzę o podatnościach wykrytych wersji oprogramowania (np. PHP, WordPress, Apache, nginx, OpenSSH, Uvicorn, frameworki).\n"
        "3. Jeśli wersja oprogramowania NIE jest znana (np. samo 'nginx' bez numeru wersji) i brak innych ryzyk, NIE wywołuj fałszywego alarmu krytycznego — ustaw urgency='low' lub 'safe' i requires_admin_alert=false.\n"
        "4. Zwróć dokładnie klucze JSON:\n"
        '   {"urgency": "critical|high|medium|low|safe", '
        '"requires_admin_alert": true|false, '
        '"title": "krótki tytuł po polsku (max 120 znaków)", '
        '"affected_software": [{"name": "...", "version": "... lub null", "port": 80, "status": "vulnerable|eol|outdated|misconfig|safe", "cves": ["CVE-..."], "reason": "krótkie wyjaśnienie"}], '
        '"cves": ["CVE-..."], '
        '"summary": "2-3 zwięzłe zdania technicznej oceny hosta po polsku", '
        '"admin_alert_message": "krótka, gotowa wiadomość alarmowa do administratora hosta (lub pusty string gdy host bezpieczny)", '
        '"remediation": "konkretne kroki aktualizacji lub hardeningu po polsku"}'
    )

    user_payload = {
        "host_telemetry": telemetry,
        "deterministic_precheck": precheck,
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://janus-asi.local",
        "X-Title": "Janus ASI Security Agent",
    }

    body: dict[str, Any] = {
        "model": cfg.model_name or DEFAULT_OPENROUTER_MODEL,
        "temperature": 0.1,
        "max_tokens": 900,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ],
    }

    with httpx.Client(timeout=35.0) as client:
        resp = client.post(url, headers=headers, json=body)
        # Niektóre modele w OpenRouter odrzucają response_format=json_object (HTTP 400) — ponów bez tego pola
        if resp.status_code == 400 and "response_format" in resp.text.lower():
            body.pop("response_format", None)
            resp = client.post(url, headers=headers, json=body)

    if resp.status_code >= 400:
        raise RuntimeError(f"OpenRouter HTTP {resp.status_code}: {resp.text[:240]}")

    data = resp.json()
    content = (
        data.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
    )
    parsed = _extract_json_object(content)

    # Normalizacja pól i gwarancja bezpiecznego schematu
    urg = str(parsed.get("urgency") or precheck["urgency"]).strip().lower()
    if urg not in ALLOWED_URGENCIES:
        urg = precheck["urgency"]
    # Jeśli deterministyczny pre-check wykrył critical/high, model nie powinien tego wyciszać poniżej poziomu faktów
    if URGENCY_RANK.get(precheck["urgency"], 1) > URGENCY_RANK.get(urg, 1):
        urg = precheck["urgency"]

    req_alert = bool(parsed.get("requires_admin_alert")) or (urg in ("critical", "high"))
    merged_cves = sorted(
        {
            str(c).strip().upper()
            for c in ([*(parsed.get("cves") or []), *(precheck.get("cves") or [])])
            if str(c).strip().upper().startswith("CVE-")
        }
    )

    raw_sw = parsed.get("affected_software")
    affected_sw = raw_sw if isinstance(raw_sw, list) else precheck["affected_software"]

    used_model = str(data.get("model") or cfg.model_name or DEFAULT_OPENROUTER_MODEL)
    result = {
        "urgency": urg,
        "requires_admin_alert": req_alert,
        "title": str(parsed.get("title") or precheck["title"]).strip()[:250],
        "affected_software": affected_sw,
        "cves": merged_cves,
        "summary": str(parsed.get("summary") or precheck["summary"]).strip(),
        "admin_alert_message": str(parsed.get("admin_alert_message") or precheck.get("admin_alert_message") or "").strip() or None,
        "remediation": str(parsed.get("remediation") or precheck.get("remediation") or "").strip() or None,
    }
    return result, f"openrouter:{used_model}"


def serialize_ai_alert(alert: AiAlert, host_override: AssetOverride | None = None) -> dict[str, Any]:
    host = alert.host
    return {
        "id": str(alert.id),
        "host_id": str(alert.host_id),
        "ip_address": str(host.ip_address).split("/")[0] if host else None,
        "hostname": host.hostname if host else None,
        "host_status": host.status if host else None,
        "owner_unit": host_override.owner_unit if host_override else None,
        "custom_label": host_override.custom_label if host_override else None,
        "scan_run_id": str(alert.scan_run_id) if alert.scan_run_id else None,
        "urgency": alert.urgency,
        "requires_admin_alert": bool(alert.requires_admin_alert),
        "title": alert.title,
        "affected_software": list(alert.affected_software or []),
        "cves": list(alert.cves or []),
        "summary": alert.summary,
        "admin_alert_message": alert.admin_alert_message,
        "remediation": alert.remediation,
        "analysis_source": alert.analysis_source,
        "acknowledged": bool(alert.acknowledged),
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        "acknowledged_by": alert.acknowledged_by,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    }


def analyze_hosts_with_ai(
    db: Session,
    *,
    host_ids: list[UUID] | None = None,
    scan_run_id: UUID | None = None,
    scope: Any = None,
    max_hosts: int = 25,
    require_configured_key: bool = True,
) -> dict[str, Any]:
    """
    Analizuje wskazane hosty (lub wszystkie aktywne w zakresie konta) przez OpenRouter AI Agent
    z uziemieniem w deterministycznym pre-checku CVE/EOL. Zapisuje wyłącznie wyniki w `ai_alerts`.
    """
    cfg = get_ai_agent_config(db)
    if require_configured_key and (cfg is None or not cfg.api_key_encrypted or not cfg.is_active):
        raise ValueError("AI Agent nie ma skonfigurowanego aktywnego klucza API OpenRouter.")

    stmt = (
        select(Host)
        .options(
            selectinload(Host.services)
            .selectinload(Service.signature_matches)
            .selectinload(SignatureMatch.signature)
        )
        .where(Host.status != "archived")
        .order_by(desc(Host.last_seen_at))
    )
    if host_ids:
        stmt = stmt.where(Host.id.in_(host_ids))
    if scope is not None:
        scope_flt = scope.sql_host_filter()
        if scope_flt is not None:
            stmt = stmt.where(scope_flt)

    hosts = db.execute(stmt.limit(max_hosts)).scalars().all()
    if not hosts:
        return {
            "analyzed_count": 0,
            "urgent_alerts_count": 0,
            "fallback_count": 0,
            "warnings": [],
            "alerts": [],
        }

    open_svc_ids = [
        s.id
        for h in hosts
        if h.status not in ("offline", "archived")
        for s in h.services
        if s.state == "open"
    ]
    latest_fp_map = fetch_latest_http_fingerprints(db, open_svc_ids)
    ov_rows = db.execute(
        select(AssetOverride).where(
            AssetOverride.entity_type == "host",
            AssetOverride.entity_id.in_([h.id for h in hosts]),
        )
    ).scalars().all()
    ov_map = {ov.entity_id: ov for ov in ov_rows}

    created_alerts: list[AiAlert] = []
    warnings: list[str] = []
    fallback_count = 0

    for h in hosts:
        ov = ov_map.get(h.id)
        telemetry = _extract_host_telemetry(h, latest_fp_map, ov)
        precheck = run_deterministic_cve_check(telemetry)

        if cfg is not None and cfg.api_key_encrypted and cfg.is_active:
            try:
                verdict, source = _call_openrouter_for_host(cfg, telemetry, precheck)
            except Exception as exc:
                logger.warning("OpenRouter AI fallback dla hosta %s: %s", telemetry["ip_address"], exc)
                verdict = precheck
                source = "deterministic-cve-fallback"
                fallback_count += 1
                err_txt = str(exc)
                if err_txt not in warnings:
                    warnings.append(err_txt)
        else:
            verdict = precheck
            source = "deterministic-cve"
            fallback_count += 1

        alert = AiAlert(
            host_id=h.id,
            scan_run_id=scan_run_id or h.last_scan_run_id,
            urgency=verdict["urgency"],
            requires_admin_alert=bool(verdict["requires_admin_alert"]),
            title=verdict["title"],
            affected_software=verdict["affected_software"],
            cves=verdict["cves"],
            summary=verdict["summary"],
            admin_alert_message=verdict["admin_alert_message"],
            remediation=verdict["remediation"],
            analysis_source=source,
            acknowledged=False,
        )
        db.add(alert)
        alert.host = h
        created_alerts.append(alert)

    db.commit()
    for a in created_alerts:
        db.refresh(a)

    created_alerts.sort(
        key=lambda a: (-URGENCY_RANK.get(a.urgency, 1), -(a.created_at.timestamp() if a.created_at else 0))
    )

    return {
        "analyzed_count": len(created_alerts),
        "urgent_alerts_count": sum(1 for a in created_alerts if a.requires_admin_alert),
        "fallback_count": fallback_count,
        "warnings": warnings,
        "alerts": [serialize_ai_alert(a, ov_map.get(a.host_id)) for a in created_alerts],
    }


def list_latest_ai_alerts(
    db: Session,
    *,
    scope: Any = None,
    host_id: UUID | None = None,
    only_urgent: bool = False,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """
    Zwraca najnowszy raport/alert AI dla każdego hosta (DISTINCT ON host_id),
    posortowany wg pilności (critical -> high -> medium -> low -> safe) i czasu.
    """
    stmt = (
        select(AiAlert)
        .join(Host, Host.id == AiAlert.host_id)
        .options(selectinload(AiAlert.host))
        .distinct(AiAlert.host_id)
        .order_by(AiAlert.host_id, desc(AiAlert.created_at))
    )
    if host_id is not None:
        stmt = stmt.where(AiAlert.host_id == host_id)
    if scope is not None:
        scope_flt = scope.sql_host_filter()
        if scope_flt is not None:
            stmt = stmt.where(scope_flt)

    rows = list(db.execute(stmt).scalars().all())
    if only_urgent:
        rows = [r for r in rows if r.requires_admin_alert]

    rows.sort(
        key=lambda a: (
            bool(a.acknowledged),
            not bool(a.requires_admin_alert),
            -URGENCY_RANK.get(a.urgency, 1),
            -(a.created_at.timestamp() if a.created_at else 0),
        )
    )
    rows = rows[:limit]

    ov_map: dict[UUID, AssetOverride] = {}
    if rows:
        ov_rows = db.execute(
            select(AssetOverride).where(
                AssetOverride.entity_type == "host",
                AssetOverride.entity_id.in_([r.host_id for r in rows]),
            )
        ).scalars().all()
        ov_map = {ov.entity_id: ov for ov in ov_rows}

    return [serialize_ai_alert(r, ov_map.get(r.host_id)) for r in rows]


def schedule_post_scan_ai_analysis(
    *,
    host_ids: list[UUID],
    scan_run_id: UUID | None,
    worker_id: str | None = None,
) -> None:
    """
    Uruchamia w tle (nieblokująco) pasywną analizę AI dla nowo przeskanowanych hostów,
    jeśli administrator zapisał klucz API OpenRouter i włączył auto-analizę po skanie.
    """
    if not host_ids:
        return
    wid = (worker_id or "").strip().lower()
    if any(wid.startswith(pref) for pref in TEST_WORKER_PREFIXES):
        return

    def _runner() -> None:
        try:
            with SessionLocal() as bg_db:
                cfg = get_ai_agent_config(bg_db)
                if cfg is None or not cfg.is_active or not cfg.auto_analyze_after_scan or not cfg.api_key_encrypted:
                    return
                analyze_hosts_with_ai(
                    bg_db,
                    host_ids=host_ids[:25],
                    scan_run_id=scan_run_id,
                    max_hosts=25,
                    require_configured_key=True,
                )
        except Exception as exc:
            logger.warning("Błąd automatycznej analizy AI po skanie: %s", exc)

    t = threading.Thread(target=_runner, name="asi-post-scan-ai", daemon=True)
    t.start()
