"""
Zestaw testów automatycznych (pytest) dla Janus ASI (Attack Surface Intelligence — CBI AGH):
  - szyfrowanie AES-256-GCM + AAD + blokada zerowego klucza,
  - JWT HS256, haszowanie scrypt, RBAC (4 role + tworzenie ról własnych) i 401 bez auth,
  - chunker CIDR (/16 -> 256x/24), scalanie nakładających się sieci, blokada SSRF i flag-injection nmap,
  - harmonogram cron i okna przechodzące przez północ,
  - testy API FastAPI (CSV ze średnikiem ';', pusty plik, PATCH null -> 422, regex RE2, dashboard summary, dry-run adaptacyjny).
"""

from datetime import datetime, time, timezone
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest

from app.core import config as cfg_mod
from app.core.crypto import (
    AAD_HTTP_HEADERS,
    AAD_OVERRIDE_NOTES,
    decrypt_field,
    decrypt_json,
    encrypt_field,
    encrypt_json,
    validate_master_key,
)
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.main import app
from app.services.chunker import (
    collapse_and_split_targets,
    detect_target_type,
    validate_nmap_flags,
    validate_ports_spec,
)
from app.services.defectdojo import validate_defectdojo_url
from app.services.scheduler import cron_matches, is_within_window, validate_cron_expression


def test_crypto_aes_gcm_with_aad_and_legacy_fallback():
    ct = encrypt_field("poufna notatka CBI AGH", associated_data=AAD_OVERRIDE_NOTES)
    assert ct[:1] == b"\x01"
    assert decrypt_field(ct, associated_data=AAD_OVERRIDE_NOTES) == "poufna notatka CBI AGH"

    # Podmiana kontekstu AAD (np. przeniesienie szyfrogramu do innej kolumny) musi zawieść
    with pytest.raises(Exception):
        decrypt_field(ct, associated_data=AAD_HTTP_HEADERS, allow_legacy_no_aad=False)

    # Zgodność wsteczna z rekordami sprzed AAD
    legacy_ct = encrypt_json({"Server": "nginx/1.27"}, associated_data=None)
    assert decrypt_json(legacy_ct, associated_data=AAD_HTTP_HEADERS) == {"Server": "nginx/1.27"}


def test_crypto_rejects_zero_key_in_strict_mode(monkeypatch):
    monkeypatch.setattr(cfg_mod.settings, "encryption_master_key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    monkeypatch.setattr(cfg_mod.settings, "allow_weak_encryption_key", False)
    with pytest.raises(RuntimeError, match="ENCRYPTION_MASTER_KEY"):
        validate_master_key()


def test_password_scrypt_and_jwt_hs256():
    pw_hash = hash_password("tajneHaslo#2026")
    assert pw_hash.startswith("scrypt$")
    assert verify_password("tajneHaslo#2026", pw_hash)
    assert not verify_password("zleHaslo", pw_hash)

    uid = uuid4()
    tok = create_access_token(user_id=uid, username="auditor", role="read_only", expires_minutes=10)
    claims = decode_access_token(tok)
    assert claims["sub"] == str(uid)
    assert claims["username"] == "auditor"
    assert claims["role"] == "read_only"

    # Manipulacja podpisem musi zostać odrzucona
    tampered = tok[:-4] + ("AAAA" if not tok.endswith("AAAA") else "BBBB")
    with pytest.raises(ValueError):
        decode_access_token(tampered)


def test_chunker_cidr_collapse_and_large_network():
    # Duża sieć /16 = 65 536 IP -> 256 paczek /24
    chunks_16, total_16 = collapse_and_split_targets([("10.10.0.0/16", "cidr")], chunk_prefix=24)
    assert total_16 == 65536
    assert len(chunks_16) == 256

    # Nakładające się sieci (172.28.0.10/31 zawiera się w 172.28.0.8/29) -> 1 paczka zamiast 2!
    collapsed, total_ips = collapse_and_split_targets(
        [("172.28.0.10/31", "cidr"), ("172.28.0.8/29", "cidr")],
        chunk_prefix=24,
    )
    assert collapsed == ["172.28.0.8/29"]
    assert total_ips == 8


def test_security_guards_nmap_targets_defectdojo():
    assert validate_nmap_flags("-sT -sV --version-light -T4 --max-retries 1") == "-sT -sV --version-light -T4 --max-retries 1"
    for bad in ("-sT --script=exploit", "-sT -oN /tmp/x", "-iL /etc/passwd", "--datadir=/tmp"):
        with pytest.raises(ValueError):
            validate_nmap_flags(bad)

    assert validate_ports_spec("80,443,8080-8090") == "80,443,8080-8090"
    with pytest.raises(ValueError):
        validate_ports_spec("80 --script=vuln")

    for bad_target in ("127.0.0.1", "169.254.169.254", "postgres", "redis", "backend", "localhost", "-sS"):
        with pytest.raises(ValueError):
            detect_target_type(bad_target)

    assert detect_target_type("172.28.0.12") == ("172.28.0.12", "ip")
    assert detect_target_type("web.agh.edu.pl") == ("web.agh.edu.pl", "domain")

    assert validate_defectdojo_url("http://host.docker.internal:8080/") == "http://host.docker.internal:8080"
    for bad_dd in ("http://169.254.169.254/latest", "http://postgres:5432", "ftp://example.com"):
        with pytest.raises(ValueError):
            validate_defectdojo_url(bad_dd)


def test_scheduler_cron_and_overnight_window():
    assert validate_cron_expression("0 22 * * *") == "0 22 * * *"
    with pytest.raises(ValueError):
        validate_cron_expression("invalid cron")

    dt_late = datetime(2026, 11, 21, 23, 30, tzinfo=timezone.utc)
    dt_early = datetime(2026, 11, 22, 3, 15, tzinfo=timezone.utc)
    dt_noon = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)

    assert is_within_window(dt_late, time(22, 0), time(6, 0))
    assert is_within_window(dt_early, time(22, 0), time(6, 0))
    assert not is_within_window(dt_noon, time(22, 0), time(6, 0))
    assert cron_matches("30 23 * * *", dt_late)


def test_api_auth_rbac_custom_roles_and_validation():
    with TestClient(app) as client:
        # 1. Publiczny healthcheck działa bez nagłówków
        r_health = client.get("/api/v1/health")
        assert r_health.status_code == 200
        assert r_health.json()["status"] == "ok"

        # 2. Chronione endpointy wymagają uwierzytelnienia (401 bez JWT i bez X-Dev-Role)
        assert client.get("/api/v1/hosts").status_code == 401
        assert client.get("/api/v1/scans/export?format=json").status_code == 401

        # 3. Prawdziwe logowanie JWT z tabeli users
        r_login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123!"})
        assert r_login.status_code == 200
        token = r_login.json()["access_token"]
        auth_headers = {"Authorization": f"Bearer {token}"}

        r_me = client.get("/api/v1/auth/me", headers=auth_headers)
        assert r_me.status_code == 200
        assert r_me.json()["auth_mode"] == "jwt"
        assert r_me.json()["role"] == "admin"

        # 4. Tworzenie własnej roli RBAC i weryfikacja jej uprawnień
        custom_role = f"test_auditor_{uuid4().hex[:6]}"
        r_create_role = client.post(
            "/api/v1/rbac/roles",
            headers=auth_headers,
            json={"name": custom_role, "description": "Rola testowa", "permissions": ["read"]},
        )
        assert r_create_role.status_code == 201
        try:
            # Własna rola ma 'read', ale NIE ma 'add'
            assert client.get("/api/v1/hosts", headers={"X-Dev-Role": custom_role}).status_code == 200
            assert client.post(
                "/api/v1/targets",
                headers={"X-Dev-Role": custom_role},
                json={"raw_value": "198.51.100.10"},
            ).status_code == 403
        finally:
            r_del_role = client.delete(f"/api/v1/rbac/roles/{custom_role}", headers=auth_headers)
            assert r_del_role.status_code == 204

        # 5. Dashboard summary (serwerowe KPI + timeline + grupowanie usług)
        r_dash = client.get("/api/v1/dashboard/summary", headers=auth_headers)
        assert r_dash.status_code == 200
        dash = r_dash.json()
        assert "kpi" in dash and "service_groups" in dash and "time_of_day_analysis" in dash

        # 6. Adaptacyjny Dry-Run dla dużej sieci /16 (65 536 IP)
        r_dry = client.post(
            "/api/v1/scans/start",
            headers=auth_headers,
            json={"raw_targets": ["10.20.0.0/16"], "adaptive_chunking": True, "window_minutes": 60, "dry_run": True},
        )
        assert r_dry.status_code == 200
        dry_body = r_dry.json()
        assert dry_body["total_target_ips"] == 65536
        assert dry_body["total_chunks"] >= 256
        assert dry_body["estimated_duration_seconds"] > 0

        # 7. Import celów CSV: pusty plik -> 400, średnik ';' -> działa poprawnie!
        r_empty = client.post(
            "/api/v1/targets/import",
            headers=auth_headers,
            files={"file": ("empty.csv", b"", "text/csv")},
        )
        assert r_empty.status_code == 400

        test_ip = f"198.51.100.{int(uuid4().hex[:2], 16) % 200 + 10}"
        r_semi = client.post(
            "/api/v1/targets/import",
            headers=auth_headers,
            files={"file": ("targets.csv", f"target;opis\n{test_ip};test_semi\n".encode(), "text/csv")},
        )
        assert r_semi.status_code == 200
        assert r_semi.json()["added"] == 1
        # Posprzątanie testowego celu
        targets_list = client.get("/api/v1/targets", headers=auth_headers).json()
        for t in targets_list:
            if t["raw_value"] == test_ip:
                client.delete(f"/api/v1/targets/{t['id']}", headers=auth_headers)

        # 8. Walidacja sygnatur: RE2 lookahead -> 422 oraz PATCH z null -> 422 (nie 500!)
        r_bad_re = client.post(
            "/api/v1/signatures",
            headers=auth_headers,
            json={"name": f"BadRE2_{uuid4().hex[:6]}", "match_type": "header", "pattern": "(?=foo)bar"},
        )
        assert r_bad_re.status_code == 422

        sigs = client.get("/api/v1/signatures", headers=auth_headers).json()
        assert len(sigs) >= 8
        r_null_patch = client.patch(
            f"/api/v1/signatures/{sigs[0]['id']}",
            headers=auth_headers,
            json={"severity": None},
        )
        assert r_null_patch.status_code == 422

        # 9. Audit logs rejestrują operacje
        r_audit = client.get("/api/v1/audit-logs?limit=10", headers=auth_headers)
        assert r_audit.status_code == 200
        assert len(r_audit.json()) > 0


def test_ingest_missed_scans_overrides_manual_signatures_and_compare():
    """Testuje pełny cykl życia hosta na syntetycznym IP (198.51.100.77) z pełnym sprzątaniem po teście."""
    from sqlalchemy import cast, select
    from sqlalchemy.dialects.postgresql import INET
    from app.db.models import AssetOverride, Host, ScanRun
    from app.db.session import SessionLocal
    from app.schemas.contract import HostResult, HTTPFingerprintResult, ScanChunkResult, ServiceResult
    from app.services.ingest import ingest_scan_result

    test_ip = "198.51.100.77"
    test_cidr = "198.51.100.76/30"
    created_run_ids: list = []

    def _cleanup():
        with SessionLocal() as db:
            h = db.execute(select(Host).where(Host.ip_address == cast(test_ip, INET))).scalar_one_or_none()
            if h:
                db.execute(
                    AssetOverride.__table__.delete().where(AssetOverride.entity_id == h.id)
                )
                db.delete(h)
            for rid in created_run_ids:
                sr = db.get(ScanRun, rid)
                if sr:
                    db.delete(sr)
            db.commit()

    _cleanup()
    try:
        now = datetime.now(timezone.utc)
        run1 = uuid4()
        created_run_ids.append(run1)

        with SessionLocal() as db:
            # Skan #1: wykrycie nowego hosta
            res1 = ingest_scan_result(
                db,
                ScanChunkResult(
                    scan_run_id=run1,
                    chunk_id=uuid4(),
                    worker_id="worker-test",
                    status="completed",
                    started_at=now,
                    finished_at=now,
                    hosts=[
                        HostResult(
                            ip=test_ip,
                            hostname="test-node.agh.local",
                            is_up=True,
                            services=[
                                ServiceResult(
                                    port=80,
                                    protocol="tcp",
                                    state="open",
                                    service_name="http",
                                    product="nginx",
                                    version="1.26.0",
                                    http=HTTPFingerprintResult(
                                        url=f"http://{test_ip}:80/",
                                        scheme="http",
                                        status_code=200,
                                        title="Before",
                                        headers={"Server": "nginx/1.26.0"},
                                        technologies=["nginx"],
                                    ),
                                )
                            ],
                        )
                    ],
                ),
                target_cidr=test_cidr,
                is_partial=False,
            )
            assert res1["hosts_processed"] == 1
            h = db.execute(select(Host).where(Host.ip_address == cast(test_ip, INET))).scalar_one()
            host_id = h.id

        # Zapis nadpisania (asset_overrides) przez API
        with TestClient(app) as client:
            hdrs = {"X-Dev-Role": "modify_read"}
            r_ov = client.patch(
                "/api/v1/overrides",
                headers=hdrs,
                json={
                    "entity_type": "host",
                    "entity_id": str(host_id),
                    "custom_label": "Kluczowy serwer testowy",
                    "notes": "Poufna notatka AES-GCM z AAD",
                    "tags": ["test-tag"],
                },
            )
            assert r_ov.status_code == 200
            assert r_ov.json()["notes"] == "Poufna notatka AES-GCM z AAD"

            # Wpis ręczny z nagłówkiem X-Powered-By powinien uruchomić pasywną sygnaturę i NIE skasować override
            r_man = client.post(
                "/api/v1/scans/manual",
                headers={"X-Dev-Role": "add_delete_modify"},
                json={
                    "ip_address": test_ip,
                    "port": 80,
                    "service_name": "http",
                    "http_status": 200,
                    "http_title": "After Manual",
                    "headers": {"X-Powered-By": "PHP/8.2.0"},
                    "cookies": ["PHPSESSID"],
                },
            )
            assert r_man.status_code == 201
            run_manual_id = r_man.json()["scan_run_id"]
            created_run_ids.append(run_manual_id)

            detail = client.get(f"/api/v1/hosts/{host_id}", headers=hdrs).json()
            assert detail["override"]["notes"] == "Poufna notatka AES-GCM z AAD"
            matched_names = {m["signature_name"] for m in detail["services"][0]["signature_matches"]}
            assert "Exposed X-Powered-By Header" in matched_names
            assert "PHP Session Cookie (PHPSESSID)" in matched_names

            # Porównanie dwóch skanów (run1 vs run_manual_id) wykrywa zmianę tytułu strony
            r_cmp = client.get(f"/api/v1/scans/compare?run_a={run1}&run_b={run_manual_id}", headers=hdrs)
            assert r_cmp.status_code == 200
            cmp_data = r_cmp.json()
            assert cmp_data["summary"]["changed"] == 1
            assert cmp_data["changed_endpoints"][0]["diffs"]["title"] == {"run_a": "Before", "run_b": "After Manual"}

        with SessionLocal() as db:
            # Przerwane okno (requeued_window) NIE zwiększa missed_scans!
            r_win = uuid4()
            created_run_ids.append(r_win)
            ingest_scan_result(
                db,
                ScanChunkResult(
                    scan_run_id=r_win,
                    chunk_id=uuid4(),
                    worker_id="worker-test",
                    status="requeued_window",
                    started_at=now,
                    finished_at=now,
                    hosts=[],
                ),
                target_cidr=test_cidr,
                is_partial=False,
            )
            h = db.get(Host, host_id)
            assert h.status == "online" and h.missed_scans == 0

            # 3 puste skany -> unstable(1), unstable(2), offline(3)
            for expected_status, expected_missed in [("unstable", 1), ("unstable", 2), ("offline", 3)]:
                rid = uuid4()
                created_run_ids.append(rid)
                ingest_scan_result(
                    db,
                    ScanChunkResult(
                        scan_run_id=rid,
                        chunk_id=uuid4(),
                        worker_id="worker-test",
                        status="completed",
                        started_at=now,
                        finished_at=now,
                        hosts=[],
                    ),
                    target_cidr=test_cidr,
                    is_partial=False,
                )
                db.refresh(h)
                assert h.status == expected_status
                assert h.missed_scans == expected_missed

            # Powrót hosta -> online (missed=0)
            rid_rec = uuid4()
            created_run_ids.append(rid_rec)
            ingest_scan_result(
                db,
                ScanChunkResult(
                    scan_run_id=rid_rec,
                    chunk_id=uuid4(),
                    worker_id="worker-test",
                    status="completed",
                    started_at=now,
                    finished_at=now,
                    hosts=[HostResult(ip=test_ip, is_up=True, services=[])],
                ),
                target_cidr=test_cidr,
                is_partial=False,
            )
            db.refresh(h)
            assert h.status == "online" and h.missed_scans == 0
    finally:
        _cleanup()


def test_explicit_closed_port_latency_diff_and_infra_defectdojo():
    """
    Testuje scenariusze z szablonu labu organizatorów:
      - natychmiastowe wykrycie zamkniętego portu TCP RST (quickstart.sh),
      - wykrywanie skoku opóźnienia HTTP / timeoutu (Toxiproxy),
      - eksport eksponowanej usługi infrastrukturalnej (Redis 6379) w DefectDojo only_interesting=True.
    """
    from sqlalchemy import cast, select
    from sqlalchemy.dialects.postgresql import INET
    from app.db.models import ChangeEvent, Host, ScanRun, Service
    from app.db.session import SessionLocal
    from app.schemas.contract import HostResult, HTTPFingerprintResult, ScanChunkResult, ServiceResult
    from app.services.defectdojo import build_per_host_generic_findings_reports
    from app.services.ingest import ingest_scan_result

    test_ip = "198.51.100.88"
    test_cidr = "198.51.100.88/32"
    created_run_ids: list = []

    def _cleanup():
        with SessionLocal() as db:
            h = db.execute(select(Host).where(Host.ip_address == cast(test_ip, INET))).scalar_one_or_none()
            if h:
                db.delete(h)
            for rid in created_run_ids:
                sr = db.get(ScanRun, rid)
                if sr:
                    db.delete(sr)
            db.commit()

    _cleanup()
    try:
        now = datetime.now(timezone.utc)
        r1, r2, r3 = uuid4(), uuid4(), uuid4()
        created_run_ids.extend([r1, r2, r3])

        with SessionLocal() as db:
            # Skan #1: port 8787 (HTTP 18ms) + port 6379 (Redis) otwarte
            ingest_scan_result(
                db,
                ScanChunkResult(
                    scan_run_id=r1,
                    chunk_id=uuid4(),
                    worker_id="worker-test",
                    status="completed",
                    started_at=now,
                    finished_at=now,
                    hosts=[
                        HostResult(
                            ip=test_ip,
                            hostname="lab-gateway.local",
                            is_up=True,
                            services=[
                                ServiceResult(
                                    port=8787,
                                    protocol="tcp",
                                    state="open",
                                    service_name="http",
                                    product="nginx",
                                    http=HTTPFingerprintResult(
                                        url=f"http://{test_ip}:8787/",
                                        scheme="http",
                                        status_code=200,
                                        response_time_ms=18,
                                        title="Quickstart App",
                                        technologies=["nginx"],
                                    ),
                                ),
                                ServiceResult(
                                    port=6379,
                                    protocol="tcp",
                                    state="open",
                                    service_name="redis",
                                    product="Redis key-value store",
                                ),
                            ],
                        )
                    ],
                ),
                target_cidr=test_cidr,
                is_partial=False,
            )

            h = db.execute(select(Host).where(Host.ip_address == cast(test_ip, INET))).scalar_one()

            # DefectDojo only_interesting=True powinien wyeksportować wystawionego Redisa (6379) jako Medium w osobnym Assecie per IP!
            dd_reports, dd_stats = build_per_host_generic_findings_reports(db, host_ids=[h.id], only_interesting=True)
            assert len(dd_reports) == 1
            assert dd_reports[0]["product_name"] == test_ip
            assert dd_stats["assets_to_export"] == 1
            redis_findings = [f for f in dd_reports[0]["payload"]["findings"] if ":6379" in f["title"]]
            assert len(redis_findings) == 1
            assert redis_findings[0]["severity"] == "Medium"
            assert "exposed-infra" in redis_findings[0]["tags"]

            # Skan #2: skok opóźnienia Toxiproxy (18ms -> 580ms) na 8787
            ingest_scan_result(
                db,
                ScanChunkResult(
                    scan_run_id=r2,
                    chunk_id=uuid4(),
                    worker_id="worker-test",
                    status="completed",
                    started_at=now,
                    finished_at=now,
                    hosts=[
                        HostResult(
                            ip=test_ip,
                            is_up=True,
                            services=[
                                ServiceResult(
                                    port=8787,
                                    protocol="tcp",
                                    state="open",
                                    service_name="http",
                                    product="nginx",
                                    http=HTTPFingerprintResult(
                                        url=f"http://{test_ip}:8787/",
                                        scheme="http",
                                        status_code=200,
                                        response_time_ms=580,
                                        title="Quickstart App",
                                        technologies=["nginx"],
                                    ),
                                ),
                                ServiceResult(port=6379, protocol="tcp", state="open", service_name="redis"),
                            ],
                        )
                    ],
                ),
                target_cidr=test_cidr,
                is_partial=False,
            )
            lat_changes = db.execute(
                select(ChangeEvent).where(ChangeEvent.scan_run_id == r2, ChangeEvent.change_type == "service_changed")
            ).scalars().all()
            assert any(
                (c.previous_value or {}).get("response_time_ms") == 18
                and (c.current_value or {}).get("response_time_ms") == 580
                for c in lat_changes
            )

            # Skan #3: port 8787 jawnie zamknięty (TCP RST -> closed) przy działającym 6379 (quickstart.sh change)
            ingest_scan_result(
                db,
                ScanChunkResult(
                    scan_run_id=r3,
                    chunk_id=uuid4(),
                    worker_id="worker-test",
                    status="completed",
                    started_at=now,
                    finished_at=now,
                    hosts=[
                        HostResult(
                            ip=test_ip,
                            is_up=True,
                            services=[
                                ServiceResult(port=8787, protocol="tcp", state="closed", service_name="http"),
                                ServiceResult(port=6379, protocol="tcp", state="open", service_name="redis"),
                            ],
                        )
                    ],
                ),
                target_cidr=test_cidr,
                is_partial=False,
            )
            svc_8787 = db.execute(select(Service).where(Service.host_id == h.id, Service.port == 8787)).scalar_one()
            svc_6379 = db.execute(select(Service).where(Service.host_id == h.id, Service.port == 6379)).scalar_one()
            assert svc_8787.state == "closed"
            assert svc_6379.state == "open"
            closed_events = db.execute(
                select(ChangeEvent).where(ChangeEvent.scan_run_id == r3, ChangeEvent.change_type == "service_closed")
            ).scalars().all()
            assert len(closed_events) == 1
    finally:
        _cleanup()


def test_defectdojo_per_ip_asset_export_and_org_mapping(monkeypatch):
    """
    Testuje model 1 IP = 1 Asset (Product) w integracji z DefectDojo API v2:
      - każde IP generuje osobny Asset (product_name = czyste IP),
      - Opcja A: owner_unit z asset_overrides -> product_type_name (fallback: domyślna organizacja),
      - istniejący w DefectDojo Asset pomija product_type_name (ochrona przed błędem 400 po ręcznym przeniesieniu),
      - nowy Asset otrzymuje best-effort PATCH opisu/tagów,
      - każdy wyeksportowany host zapisuje własny rekord w defectdojo_exports z host_id i defectdojo_product_id.
    """
    from sqlalchemy import cast, select
    from sqlalchemy.dialects.postgresql import INET
    from app.core.crypto import AAD_INTEGRATION_TOKEN, encrypt_field
    from app.db.models import AssetOverride, DefectDojoExport, Host, Integration, ScanRun
    from app.db.session import SessionLocal
    from app.schemas.contract import HostResult, ScanChunkResult, ServiceResult
    import app.services.defectdojo as dd_mod
    from app.services.ingest import ingest_scan_result

    ip_new = "198.51.100.91"
    ip_existing = "198.51.100.92"
    run_id = uuid4()
    created_integration = False
    saved_prev_int: dict | None = None

    def _cleanup():
        with SessionLocal() as db:
            for ip in (ip_new, ip_existing):
                h = db.execute(select(Host).where(Host.ip_address == cast(ip, INET))).scalar_one_or_none()
                if h:
                    for ov in db.execute(select(AssetOverride).where(AssetOverride.entity_id == h.id)).scalars().all():
                        db.delete(ov)
                    for ex in db.execute(select(DefectDojoExport).where(DefectDojoExport.host_id == h.id)).scalars().all():
                        db.delete(ex)
                    db.delete(h)
            sr = db.get(ScanRun, run_id)
            if sr:
                db.delete(sr)
            integ = dd_mod.get_defectdojo_integration(db)
            if created_integration and integ:
                db.delete(integ)
            elif saved_prev_int and integ:
                integ.base_url = saved_prev_int["base_url"]
                integ.product_type_name = saved_prev_int["product_type_name"]
                integ.engagement_name = saved_prev_int["engagement_name"]
                integ.is_active = saved_prev_int["is_active"]
            db.commit()

    _cleanup()
    try:
        now = datetime.now(timezone.utc)
        with SessionLocal() as db:
            ingest_scan_result(
                db,
                ScanChunkResult(
                    scan_run_id=run_id,
                    chunk_id=uuid4(),
                    worker_id="worker-test",
                    status="completed",
                    started_at=now,
                    finished_at=now,
                    hosts=[
                        HostResult(
                            ip=ip_new,
                            hostname="wieit-app.agh.edu.pl",
                            is_up=True,
                            services=[ServiceResult(port=80, protocol="tcp", state="open", service_name="http", product="nginx")],
                        ),
                        HostResult(
                            ip=ip_existing,
                            hostname="default-srv.agh.edu.pl",
                            is_up=True,
                            services=[ServiceResult(port=443, protocol="tcp", state="open", service_name="https", product="nginx")],
                        ),
                    ],
                ),
                is_partial=False,
            )

            h_new = db.execute(select(Host).where(Host.ip_address == cast(ip_new, INET))).scalar_one()
            h_existing = db.execute(select(Host).where(Host.ip_address == cast(ip_existing, INET))).scalar_one()

            db.add(
                AssetOverride(
                    entity_type="host",
                    entity_id=h_new.id,
                    custom_label="Serwer WIEiT",
                    owner_unit="WIEiT",
                    tags=["wydzial-wieit"],
                )
            )

            integ = dd_mod.get_defectdojo_integration(db)
            if integ is None:
                created_integration = True
                integ = Integration(
                    name=dd_mod.DEFECTDOJO_INTEGRATION_NAME,
                    provider="defectdojo",
                    base_url="http://host.docker.internal:8080",
                    api_token_encrypted=encrypt_field("test-dd-token", associated_data=AAD_INTEGRATION_TOKEN),
                    product_type_name="AGH Attack Surface",
                    engagement_name="Janus ASI — Attack Surface",
                    verify_tls=False,
                    is_active=True,
                )
                db.add(integ)
            else:
                saved_prev_int = {
                    "base_url": integ.base_url,
                    "product_type_name": integ.product_type_name,
                    "engagement_name": integ.engagement_name,
                    "is_active": integ.is_active,
                }
                integ.product_type_name = "AGH Attack Surface"
                integ.engagement_name = "Janus ASI — Attack Surface"
                integ.is_active = True
            db.commit()

            # 1. Dry-Run weryfikuje podział na 2 osobne Assety i mapowanie Organizacji (Opcja A)
            dry = dd_mod.export_to_defectdojo(db, host_ids=[h_new.id, h_existing.id], dry_run=True)
            assert dry["mode"] == "per_host_asset"
            assert dry["stats"]["assets_to_export"] == 2
            by_ip = {a["product_name"]: a for a in dry["assets"]}
            assert by_ip[ip_new]["product_type_name"] == "WIEiT"
            assert by_ip[ip_new]["product_type_source"] == "owner_unit"
            assert by_ip[ip_existing]["product_type_name"] == "AGH Attack Surface"
            assert by_ip[ip_existing]["product_type_source"] == "default"

            # 2. Mockowany realny eksport weryfikuje auto_create_context i ochronę istniejącego Assetu przed konfliktem 400
            recorded_posts: list[dict] = []
            recorded_patches: list[tuple[str, dict]] = []

            class _FakeResp:
                def __init__(self, status_code: int, payload: dict):
                    self.status_code = status_code
                    self._payload = payload
                    self.headers = {"content-type": "application/json"}
                    self.text = str(payload)

                def json(self):
                    return self._payload

            class _FakeClient:
                def __init__(self, *args, **kwargs):
                    pass

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return False

                def get(self, url, params=None, headers=None):
                    if url.endswith("/api/v2/products/") and params and params.get("name_exact") == ip_existing:
                        return _FakeResp(200, {"count": 1, "results": [{"id": 42, "name": ip_existing}]})
                    return _FakeResp(200, {"count": 0, "results": []})

                def post(self, url, headers=None, data=None, files=None):
                    recorded_posts.append(dict(data or {}))
                    pname = (data or {}).get("product_name")
                    if pname == ip_new:
                        return _FakeResp(201, {"product_id": 101, "product_type_id": 7, "engagement_id": 201, "test_id": 301})
                    return _FakeResp(201, {"product_id": 42, "product_type_id": 9, "engagement_id": 202, "test_id": 302})

                def patch(self, url, headers=None, json=None):
                    recorded_patches.append((url, dict(json or {})))
                    return _FakeResp(200, {"id": 101})

            monkeypatch.setattr(dd_mod.httpx, "Client", _FakeClient)

            res = dd_mod.export_to_defectdojo(db, host_ids=[h_new.id, h_existing.id], dry_run=False)
            assert res["exported"] is True
            assert res["partial_failure"] is False
            assert res["stats"]["assets_exported"] == 2
            assert res["stats"]["assets_created"] == 1
            assert res["stats"]["assets_updated"] == 1

            posts_by_prod = {p["product_name"]: p for p in recorded_posts}
            assert posts_by_prod[ip_new]["product_type_name"] == "WIEiT"
            assert posts_by_prod[ip_new]["auto_create_context"] == "true"
            assert "product_type_name" not in posts_by_prod[ip_existing]
            assert posts_by_prod[ip_existing]["auto_create_context"] == "true"

            # PATCH tylko dla nowo utworzonego Assetu (101), bez nadpisywania istniejącego (42)
            assert len(recorded_patches) == 1
            assert recorded_patches[0][0].endswith("/api/v2/products/101/")
            assert "wydzial-wieit" in recorded_patches[0][1]["tags"]

            # W tabeli defectdojo_exports zapisano 2 osobne rekordy z host_id i defectdojo_product_id
            exp_rows = db.execute(
                select(DefectDojoExport).where(DefectDojoExport.host_id.in_([h_new.id, h_existing.id]))
            ).scalars().all()
            assert len(exp_rows) == 2
            exp_map = {r.product_name: r for r in exp_rows}
            assert exp_map[ip_new].defectdojo_product_id == 101
            assert exp_map[ip_existing].defectdojo_product_id == 42
    finally:
        _cleanup()


def test_signatures_import_export_tester_and_artifacts():
    """
    Testuje rozbudowany moduł sygnatur:
      - eksport JSON (przenośny format bez UUID, filtry only_enabled/ids, RBAC read_only),
      - zbiorczy import JSON (dry_run, skip, overwrite, error, normalizacja aliasów, odrzucanie ReDoS/SSRF, import-file),
      - Live Tester (próbka + test wsteczny na bazie) oraz endpoint observed-artifacts.
    """
    from sqlalchemy import select
    from app.db.models import CustomSignature
    from app.db.session import SessionLocal

    suffix = uuid4().hex[:6]
    sig_a = f"TestHdrAlias_{suffix}"
    sig_b = f"TestPathNoPattern_{suffix}"
    sig_c = f"TestCookieFile_{suffix}"
    created_names = [sig_a, sig_b, sig_c]

    def _cleanup():
        with SessionLocal() as db:
            rows = db.execute(select(CustomSignature).where(CustomSignature.name.in_(created_names))).scalars().all()
            for r in rows:
                db.delete(r)
            db.commit()

    _cleanup()
    try:
        with TestClient(app) as client:
            admin_hdr = {"X-Dev-Role": "admin"}
            ro_hdr = {"X-Dev-Role": "read_only"}
            mod_hdr = {"X-Dev-Role": "modify_read"}

            # 1. RBAC: read_only i modify_read mogą eksportować, ale NIE mogą importować
            r_exp_ro = client.get("/api/v1/signatures/export?only_enabled=true", headers=ro_hdr)
            assert r_exp_ro.status_code == 200
            exp_data = r_exp_ro.json()
            assert exp_data["schema_version"] == "1.0"
            assert exp_data["count"] >= 8
            assert "id" not in exp_data["signatures"][0]

            r_imp_ro = client.post("/api/v1/signatures/import", headers=ro_hdr, json=[{"name": sig_a, "match_type": "cookie", "pattern": "X"}])
            assert r_imp_ro.status_code == 403
            r_imp_mod = client.post("/api/v1/signatures/import", headers=mod_hdr, json=[{"name": sig_a, "match_type": "cookie", "pattern": "X"}])
            assert r_imp_mod.status_code == 403

            # 2. Dry-Run z aliasami pól, pustym patternem dla path_probe oraz 2 błędnymi wpisami (ReDoS i SSRF)
            import_bundle = {
                "signatures": [
                    {
                        "name": sig_a,
                        "type": "header_match",
                        "header_name": "X-Test-Header",
                        "value": "staging",
                        "severity": "med",
                        "enabled": True,
                    },
                    {
                        "name": sig_b,
                        "type": "path",
                        "path": "/metrics",
                        "status": 200,
                        "pattern": "",
                        "severity": "low",
                    },
                    {
                        "name": f"BadRE2_{suffix}",
                        "match_type": "header",
                        "pattern": "(?=lookahead)bad",
                    },
                    {
                        "name": f"BadSSRF_{suffix}",
                        "match_type": "path_probe",
                        "probe_path": "http://169.254.169.254/latest",
                        "pattern": "meta",
                    },
                ]
            }
            r_dry = client.post("/api/v1/signatures/import?dry_run=true&on_conflict=skip", headers=admin_hdr, json=import_bundle)
            assert r_dry.status_code == 200
            dry = r_dry.json()
            assert dry["dry_run"] is True
            assert dry["summary"]["created"] == 2
            assert dry["summary"]["errors"] == 2

            # Po dry_run nic nie zostało zapisane w bazie
            with SessionLocal() as db:
                assert db.execute(select(CustomSignature).where(CustomSignature.name == sig_a)).scalar_one_or_none() is None

            # 3. Faktyczny import (skip) — zapisuje 2 poprawne, raportuje 2 błędy
            r_imp = client.post("/api/v1/signatures/import?on_conflict=skip", headers=admin_hdr, json=import_bundle)
            assert r_imp.status_code == 200
            imp = r_imp.json()
            assert imp["summary"]["created"] == 2
            assert imp["summary"]["errors"] == 2

            # 4. Ponowny import w trybie skip -> pomija istniejące
            r_skip = client.post("/api/v1/signatures/import?on_conflict=skip", headers=admin_hdr, json=import_bundle["signatures"][:2])
            assert r_skip.status_code == 200
            assert r_skip.json()["summary"]["skipped"] == 2
            assert r_skip.json()["summary"]["created"] == 0

            # 5. Tryb error -> 409 i brak zapisu
            r_err = client.post("/api/v1/signatures/import?on_conflict=error", headers=admin_hdr, json=[{"name": sig_a, "match_type": "cookie", "pattern": "NEW"}])
            assert r_err.status_code == 409

            # 6. Tryb overwrite -> nadpisuje istniejącą sygnaturę
            r_over = client.post(
                "/api/v1/signatures/import?on_conflict=overwrite",
                headers=admin_hdr,
                json=[{"name": sig_a, "match_type": "header", "pattern": "(?i)^X-Test-Header:\\s*prod$", "severity": "high", "description": "Updated"}],
            )
            assert r_over.status_code == 200
            assert r_over.json()["summary"]["updated"] == 1

            # 7. Import z pliku (.json)
            file_json = f'{{"signatures":[{{"name":"{sig_c}","type":"cookie_name","value":"CUSTOM_SESS","severity":"info"}}]}}'
            r_file = client.post(
                "/api/v1/signatures/import-file",
                headers=admin_hdr,
                files={"file": ("sigs.json", file_json.encode("utf-8"), "application/json")},
            )
            assert r_file.status_code == 200
            assert r_file.json()["summary"]["created"] == 1

            # 8. Eksport konkretnego ID z download=true
            all_sigs = client.get("/api/v1/signatures", headers=ro_hdr).json()
            sig_a_obj = next(s for s in all_sigs if s["name"] == sig_a)
            assert sig_a_obj["severity"] == "high"
            r_exp_one = client.get(f"/api/v1/signatures/export?ids={sig_a_obj['id']}&download=true", headers=ro_hdr)
            assert r_exp_one.status_code == 200
            assert "attachment" in r_exp_one.headers.get("content-disposition", "")
            assert r_exp_one.json()["count"] == 1
            assert r_exp_one.json()["signatures"][0]["name"] == sig_a

            # 9. Live Tester (próbka header, path_probe bez patternu, test_against_db)
            r_test_hdr = client.post(
                "/api/v1/signatures/test",
                headers=ro_hdr,
                json={
                    "match_type": "header",
                    "pattern": r"(?i)^X-Powered-By:\s*.*PHP",
                    "sample_headers": "Server: nginx\nX-Powered-By: PHP/7.4.33",
                    "test_against_db": True,
                },
            )
            assert r_test_hdr.status_code == 200
            t_hdr = r_test_hdr.json()
            assert t_hdr["sample_match"] is True
            assert "PHP/7.4.33" in (t_hdr["sample_evidence"] or "")
            assert t_hdr["db_test"]["supported"] is True

            r_test_path = client.post(
                "/api/v1/signatures/test",
                headers=ro_hdr,
                json={
                    "match_type": "path_probe",
                    "probe_path": "/metrics",
                    "expected_status": 200,
                    "pattern": "",
                    "sample_status_code": 200,
                    "test_against_db": True,
                },
            )
            assert r_test_path.status_code == 200
            assert r_test_path.json()["sample_match"] is True
            assert r_test_path.json()["db_test"]["supported"] is False

            # 10. Observed artifacts endpoint
            r_art = client.get("/api/v1/signatures/observed-artifacts", headers=ro_hdr)
            assert r_art.status_code == 200
            art = r_art.json()
            assert "header_names" in art and "cookies" in art and "favicons" in art
    finally:
        _cleanup()


def test_automatic_groups_smart_groups_targeted_scan_and_port_protection():
    """
    Testuje Automatyczne Grupy (Auto-Groups & Smart Groups):
      - auto-wykrywanie grup dla WordPress i portu 8080,
      - podgląd łączonych reguł (AND/OR),
      - CRUD zapisanych Smart Groups + RBAC + podpięcie pod harmonogram,
      - celowany skan grupy (dry_run z domyślnym pełnym profilem oraz matched_ports),
      - ochronę nieskanowanych portów w ingest.py (skan samego 8080 nie zamyka otwartego portu 80).
    """
    from sqlalchemy import cast, select
    from sqlalchemy.dialects.postgresql import INET
    from app.db.models import Host, ScanRun, ScanSchedule, Service, TargetGroup
    from app.db.session import SessionLocal
    from app.schemas.contract import HostResult, HTTPFingerprintResult, ScanChunkResult, ServiceResult
    from app.services.ingest import ingest_scan_result
    from app.services.seed import ensure_default_group_and_profile

    suffix = uuid4().hex[:6]
    ip_wp_80 = "198.51.100.141"
    ip_wp_8080 = "198.51.100.142"
    ip_apache_8080 = "198.51.100.143"
    test_ips = [ip_wp_80, ip_wp_8080, ip_apache_8080]
    grp_name = f"WordPress_Smart_{suffix}"
    sched_name = f"Sched_WP_{suffix}"
    created_run_ids: list = []

    def _cleanup():
        with SessionLocal() as db:
            sc = db.execute(select(ScanSchedule).where(ScanSchedule.name == sched_name)).scalar_one_or_none()
            if sc:
                db.delete(sc)
            tg = db.execute(select(TargetGroup).where(TargetGroup.name == grp_name)).scalar_one_or_none()
            if tg:
                db.delete(tg)
            for ip in test_ips:
                h = db.execute(select(Host).where(Host.ip_address == cast(ip, INET))).scalar_one_or_none()
                if h:
                    db.delete(h)
            for rid in created_run_ids:
                sr = db.get(ScanRun, rid)
                if sr:
                    db.delete(sr)
            db.commit()

    _cleanup()
    try:
        now = datetime.now(timezone.utc)
        seed_run = uuid4()
        created_run_ids.append(seed_run)

        with SessionLocal() as db:
            ingest_scan_result(
                db,
                ScanChunkResult(
                    scan_run_id=seed_run,
                    chunk_id=uuid4(),
                    worker_id="worker-test",
                    status="completed",
                    started_at=now,
                    finished_at=now,
                    hosts=[
                        HostResult(
                            ip=ip_wp_80,
                            hostname="wp1.agh.local",
                            is_up=True,
                            services=[
                                ServiceResult(
                                    port=80,
                                    protocol="tcp",
                                    state="open",
                                    service_name="http",
                                    product="nginx",
                                    http=HTTPFingerprintResult(
                                        url=f"http://{ip_wp_80}:80/",
                                        scheme="http",
                                        status_code=200,
                                        title="AGH Blog",
                                        technologies=["WordPress", "PHP"],
                                        is_admin_panel=True,
                                    ),
                                ),
                                ServiceResult(port=22, protocol="tcp", state="open", service_name="ssh", product="OpenSSH"),
                            ],
                        ),
                        HostResult(
                            ip=ip_wp_8080,
                            hostname="wp2.agh.local",
                            is_up=True,
                            services=[
                                ServiceResult(
                                    port=80,
                                    protocol="tcp",
                                    state="open",
                                    service_name="http",
                                    product="nginx",
                                    http=HTTPFingerprintResult(
                                        url=f"http://{ip_wp_8080}:80/",
                                        scheme="http",
                                        status_code=200,
                                        technologies=["nginx"],
                                    ),
                                ),
                                ServiceResult(
                                    port=8080,
                                    protocol="tcp",
                                    state="open",
                                    service_name="http",
                                    product="Apache",
                                    http=HTTPFingerprintResult(
                                        url=f"http://{ip_wp_8080}:8080/",
                                        scheme="http",
                                        status_code=200,
                                        technologies=["WordPress"],
                                    ),
                                ),
                            ],
                        ),
                        HostResult(
                            ip=ip_apache_8080,
                            hostname="app8080.agh.local",
                            is_up=True,
                            services=[
                                ServiceResult(
                                    port=8080,
                                    protocol="tcp",
                                    state="open",
                                    service_name="http",
                                    product="Apache",
                                    http=HTTPFingerprintResult(
                                        url=f"http://{ip_apache_8080}:8080/",
                                        scheme="http",
                                        status_code=200,
                                        technologies=["Apache HTTP Server"],
                                    ),
                                )
                            ],
                        ),
                    ],
                ),
                is_partial=False,
            )

        with TestClient(app) as client:
            admin_hdr = {"X-Dev-Role": "admin"}
            ro_hdr = {"X-Dev-Role": "read_only"}

            # 1. Auto-wykrywanie grup na żywo (WordPress + Port 8080)
            r_auto = client.get("/api/v1/groups/auto", headers=ro_hdr)
            assert r_auto.status_code == 200
            auto = r_auto.json()
            by_key = {g["key"]: g for g in auto["groups"]}
            assert "tech:wordpress" in by_key
            assert set([ip_wp_80, ip_wp_8080]).issubset(set(by_key["tech:wordpress"]["sample_ips"]))
            assert "port:8080" in by_key
            assert set([ip_wp_8080, ip_apache_8080]).issubset(set(by_key["port:8080"]["sample_ips"]))

            # 2. Preview łączonych reguł: WordPress AND port 8080 -> tylko ip_wp_8080
            r_prev_and = client.post(
                "/api/v1/groups/preview",
                headers=ro_hdr,
                json={"match_mode": "all", "technologies": ["WordPress"], "ports": [8080], "cidr_scope": "198.51.100.140/30"},
            )
            assert r_prev_and.status_code == 200
            assert r_prev_and.json()["ips"] == [ip_wp_8080]

            # WordPress OR port 8080 -> wszystkie 3 testowe hosty
            r_prev_or = client.post(
                "/api/v1/groups/preview",
                headers=ro_hdr,
                json={"match_mode": "any", "technologies": ["WordPress"], "ports": [8080], "cidr_scope": "198.51.100.140/30"},
            )
            assert r_prev_or.status_code == 200
            assert set(r_prev_or.json()["ips"]) == set(test_ips)

            # 3. RBAC: read_only nie może tworzyć ani skanować grupy
            assert client.post(
                "/api/v1/groups",
                headers=ro_hdr,
                json={"name": grp_name, "filter_rules": {"technologies": ["WordPress"]}},
            ).status_code == 403
            assert client.post(
                "/api/v1/groups/scan",
                headers=ro_hdr,
                json={"filter_rules": {"technologies": ["WordPress"]}, "dry_run": True},
            ).status_code == 403

            # 4. Zapisanie Smart Group (WordPress w testowym CIDR)
            r_create = client.post(
                "/api/v1/groups",
                headers=admin_hdr,
                json={
                    "name": grp_name,
                    "description": "Hosty z WordPressem",
                    "environment": "prod",
                    "filter_rules": {"technologies": ["WordPress"], "cidr_scope": "198.51.100.140/30"},
                },
            )
            assert r_create.status_code == 201
            grp_data = r_create.json()
            grp_id = grp_data["id"]
            assert grp_data["group_type"] == "dynamic"
            assert grp_data["member_count"] == 2
            assert set(grp_data["sample_ips"]) == {ip_wp_80, ip_wp_8080}

            # 5. Skan grupy (domyślny tryb = pełny profil, oraz tryb matched_ports)
            r_scan_prof = client.post(
                "/api/v1/groups/scan",
                headers=admin_hdr,
                json={"group_id": grp_id, "dry_run": True},
            )
            assert r_scan_prof.status_code == 200
            sp = r_scan_prof.json()
            assert sp["ports_mode"] == "profile"
            assert sp["matched_hosts_count"] == 2
            assert set(sp["matched_ips"]) == {ip_wp_80, ip_wp_8080}

            r_scan_8080 = client.post(
                "/api/v1/groups/scan",
                headers=admin_hdr,
                json={"filter_rules": {"ports": [8080], "cidr_scope": "198.51.100.140/30"}, "ports_mode": "matched_ports", "dry_run": True},
            )
            assert r_scan_8080.status_code == 200
            assert r_scan_8080.json()["ports"] == "8080"
            assert set(r_scan_8080.json()["matched_ips"]) == {ip_wp_8080, ip_apache_8080}

            # 6. Standardowy /scans/start z target_group_id dynamicznej grupy też działa!
            r_std_start = client.post(
                "/api/v1/scans/start",
                headers=admin_hdr,
                json={"target_group_id": grp_id, "dry_run": True},
            )
            assert r_std_start.status_code == 200
            assert r_std_start.json()["total_target_ips"] == 2

            # 7. Podpięcie Smart Group pod harmonogram cykliczny
            r_sched = client.post(
                "/api/v1/schedules",
                headers=admin_hdr,
                json={
                    "name": sched_name,
                    "target_group_id": grp_id,
                    "cron_expression": "0 23 * * *",
                    "window_start": "22:00",
                    "window_end": "06:00",
                },
            )
            assert r_sched.status_code == 201
            sched_out = r_sched.json()
            assert sched_out["target_group_name"] == grp_name
            assert sched_out["target_group_type"] == "dynamic"

        # 8. Ochrona nieskanowanych portów: skan wyłącznie portu 8080 NIE może zamykać portu 80 na ip_wp_8080!
        with SessionLocal() as db:
            default_grp, default_prof = ensure_default_group_and_profile(db)
            for _ in range(3):
                rid = uuid4()
                created_run_ids.append(rid)
                db.add(
                    ScanRun(
                        id=rid,
                        target_group_id=default_grp.id,
                        profile_id=default_prof.id,
                        status="running",
                        scanned_ports="8080",
                        total_chunks=1,
                        completed_chunks=0,
                    )
                )
                db.flush()
                # Host odpowiada tylko na porcie 8080 (port 80 nie był skanowany!)
                ingest_scan_result(
                    db,
                    ScanChunkResult(
                        scan_run_id=rid,
                        chunk_id=uuid4(),
                        worker_id="worker-test",
                        status="completed",
                        started_at=now,
                        finished_at=now,
                        hosts=[HostResult(ip=ip_wp_8080, is_up=True, services=[])],
                    ),
                    target_cidr=f"{ip_wp_8080}/32",
                    is_partial=False,
                )

            h2 = db.execute(select(Host).where(Host.ip_address == cast(ip_wp_8080, INET))).scalar_one()
            svc_80 = db.execute(select(Service).where(Service.host_id == h2.id, Service.port == 80)).scalar_one()
            svc_8080 = db.execute(select(Service).where(Service.host_id == h2.id, Service.port == 8080)).scalar_one()
            assert svc_80.state == "open" and svc_80.missed_scans == 0
            assert svc_8080.state == "closed" and svc_8080.missed_scans == 3
    finally:
        _cleanup()


def test_user_scope_visibility_and_enforcement():
    """
    Test end-to-end ograniczania widoczności per konto użytkownika (Asset Scope / ABAC):
      - fail-closed dla pustego ograniczonego zakresu (0 hostów, 0 KPI),
      - edycja konta PATCH /rbac/users/{id} + podgląd na żywo /rbac/users/scope-preview
        (przypisanie pojedynczego IP, zakresu start-koniec oraz dynamicznej Smart Group),
      - egzekwowanie zakresu na /hosts, /hosts/{id}, /dashboard/summary, /changes,
        /overrides, /groups/auto, /scans/start (w tym blokada szerszego CIDR),
        /scans/export oraz /integrations/defectdojo/export,
      - blokada eskalacji uprawnień przez ograniczonego admina (nie może zdjąć sobie zakresu
        ani zmienić reguł grupy przypisanej do swojego zakresu).
    """
    from sqlalchemy import cast, delete, select
    from sqlalchemy.dialects.postgresql import INET
    from app.db.models import AssetOverride, ChangeEvent, Host, ScanRun, TargetGroup, User
    from app.db.session import SessionLocal
    from app.schemas.contract import HostResult, HTTPFingerprintResult, ScanChunkResult, ServiceResult
    from app.services.ingest import ingest_scan_result

    octet = (int(uuid4().hex[:2], 16) % 150) + 50
    ip_explicit = f"198.51.{octet}.10"
    ip_in_range = f"198.51.{octet}.22"
    ip_range_spec = f"198.51.{octet}.20-198.51.{octet}.25"
    ip_in_group = f"198.51.{octet}.30"
    ip_forbidden = f"198.51.{octet}.99"
    all_ips = [ip_explicit, ip_in_range, ip_in_group, ip_forbidden]

    unique_tag = f"ScopeTech-{uuid4().hex[:6]}"
    forbidden_tech = f"SecretTech-{uuid4().hex[:6]}"
    grp_name = f"scope-smart-{uuid4().hex[:8]}"
    scoped_username = f"scoped_adm_{uuid4().hex[:8]}"
    scoped_email = f"{scoped_username}@cbi.agh.edu.pl"
    scoped_pass = "ScopedPass123!"
    now = datetime.now(timezone.utc)
    created_run_id = uuid4()

    def _cleanup():
        with SessionLocal() as db:
            db.execute(delete(User).where(User.username == scoped_username))
            db.execute(delete(TargetGroup).where(TargetGroup.name == grp_name))
            h_ids = list(
                db.execute(select(Host.id).where(Host.ip_address.in_([cast(ip, INET) for ip in all_ips]))).scalars().all()
            )
            if h_ids:
                db.execute(delete(AssetOverride).where(AssetOverride.entity_id.in_(h_ids)))
                db.execute(delete(Host).where(Host.id.in_(h_ids)))
            db.execute(delete(ScanRun).where(ScanRun.id == created_run_id))
            db.commit()

    _cleanup()
    try:
        # 1. Zasiej 4 hosty testowe przez ingest pipeline
        with SessionLocal() as db:
            ingest_scan_result(
                db,
                ScanChunkResult(
                    scan_run_id=created_run_id,
                    chunk_id=uuid4(),
                    worker_id="worker-scope-test",
                    status="completed",
                    started_at=now,
                    finished_at=now,
                    hosts=[
                        HostResult(
                            ip=ip_explicit,
                            hostname="explicit.scope.local",
                            is_up=True,
                            services=[
                                ServiceResult(
                                    port=80,
                                    protocol="tcp",
                                    state="open",
                                    service_name="http",
                                    product="nginx",
                                    http=HTTPFingerprintResult(
                                        url=f"http://{ip_explicit}/",
                                        scheme="http",
                                        status_code=200,
                                        title="Explicit Host",
                                        technologies=["nginx"],
                                    ),
                                )
                            ],
                        ),
                        HostResult(
                            ip=ip_in_range,
                            hostname="range.scope.local",
                            is_up=True,
                            services=[
                                ServiceResult(
                                    port=8080,
                                    protocol="tcp",
                                    state="open",
                                    service_name="http",
                                    product="caddy",
                                    http=HTTPFingerprintResult(
                                        url=f"http://{ip_in_range}:8080/",
                                        scheme="http",
                                        status_code=200,
                                        title="Range Host",
                                        technologies=["Caddy"],
                                    ),
                                )
                            ],
                        ),
                        HostResult(
                            ip=ip_in_group,
                            hostname="group.scope.local",
                            is_up=True,
                            services=[
                                ServiceResult(
                                    port=443,
                                    protocol="tcp",
                                    state="open",
                                    service_name="https",
                                    product="apache",
                                    http=HTTPFingerprintResult(
                                        url=f"https://{ip_in_group}/",
                                        scheme="https",
                                        status_code=200,
                                        title="Group Host",
                                        technologies=[unique_tag],
                                    ),
                                )
                            ],
                        ),
                        HostResult(
                            ip=ip_forbidden,
                            hostname="secret.scope.local",
                            is_up=True,
                            services=[
                                ServiceResult(
                                    port=8443,
                                    protocol="tcp",
                                    state="open",
                                    service_name="https",
                                    product="secret-srv",
                                    http=HTTPFingerprintResult(
                                        url=f"https://{ip_forbidden}:8443/",
                                        scheme="https",
                                        status_code=200,
                                        title="Secret Host",
                                        technologies=[forbidden_tech],
                                        is_admin_panel=True,
                                    ),
                                )
                            ],
                        ),
                    ],
                ),
                target_cidr=f"198.51.{octet}.0/24",
                is_partial=True,
            )

        with SessionLocal() as db:
            h_explicit = db.execute(select(Host).where(Host.ip_address == cast(ip_explicit, INET))).scalar_one()
            h_forbidden = db.execute(select(Host).where(Host.ip_address == cast(ip_forbidden, INET))).scalar_one()
            ev_forbidden = db.execute(
                select(ChangeEvent).where(ChangeEvent.host_id == h_forbidden.id).limit(1)
            ).scalar_one()
            explicit_id = str(h_explicit.id)
            forbidden_id = str(h_forbidden.id)
            forbidden_ev_id = str(ev_forbidden.id)

        with TestClient(app) as client:
            admin_hdr = {"X-Dev-Role": "admin"}

            # 2. Utwórz Smart Group dopasowującą wyłącznie ip_in_group
            r_grp = client.post(
                "/api/v1/groups",
                headers=admin_hdr,
                json={
                    "name": grp_name,
                    "filter_rules": {"technologies": [unique_tag], "statuses": ["online"]},
                },
            )
            assert r_grp.status_code == 201, r_grp.text
            grp_id = r_grp.json()["id"]

            # 3. Utwórz konto admin z ograniczonym (na start pustym) zakresem
            r_usr = client.post(
                "/api/v1/rbac/users",
                headers=admin_hdr,
                json={
                    "username": scoped_username,
                    "email": scoped_email,
                    "password": scoped_pass,
                    "role_name": "admin",
                    "scope_restricted": True,
                },
            )
            assert r_usr.status_code == 201, r_usr.text
            scoped_uid = r_usr.json()["id"]
            assert r_usr.json()["scope_restricted"] is True
            assert r_usr.json()["scope_summary"]["matched_hosts_count"] == 0

            # 4. Logowanie JWT jako ograniczony admin -> fail-closed (0 hostów!)
            r_login = client.post(
                "/api/v1/auth/login",
                json={"username": scoped_username, "password": scoped_pass},
            )
            assert r_login.status_code == 200, r_login.text
            assert r_login.json()["scope_restricted"] is True
            scoped_hdr = {"Authorization": f"Bearer {r_login.json()['access_token']}"}

            r_empty_hosts = client.get("/api/v1/hosts", headers=scoped_hdr)
            assert r_empty_hosts.status_code == 200
            assert r_empty_hosts.json() == []
            assert r_empty_hosts.headers.get("X-Total-Count") == "0"
            assert client.get("/api/v1/dashboard/summary", headers=scoped_hdr).json()["kpi"]["total_hosts"] == 0

            # 5. Podgląd zakresu i zapis (PATCH /rbac/users/{id}): 1 IP + zakres start-end + Smart Group
            draft_scope = {
                "ips": [ip_explicit],
                "cidrs": [],
                "ip_ranges": [ip_range_spec],
                "group_ids": [grp_id],
                "host_ids": [],
            }
            r_prev = client.post(
                "/api/v1/rbac/users/scope-preview",
                headers=admin_hdr,
                json={"scope_restricted": True, "allowed_scope": draft_scope},
            )
            assert r_prev.status_code == 200, r_prev.text
            assert r_prev.json()["scope_summary"]["matched_hosts_count"] == 3
            assert set(r_prev.json()["scope_summary"]["sample_ips"]) == {ip_explicit, ip_in_range, ip_in_group}

            r_patch = client.patch(
                f"/api/v1/rbac/users/{scoped_uid}",
                headers=admin_hdr,
                json={"scope_restricted": True, "allowed_scope": draft_scope},
            )
            assert r_patch.status_code == 200, r_patch.text
            assert r_patch.json()["scope_summary"]["matched_hosts_count"] == 3

            # 6. Ten sam token JWT NATYCHMIAST widzi dokładnie 3 dozwolone hosty i ZERO danych o ip_forbidden
            r_hosts = client.get("/api/v1/hosts?limit=500", headers=scoped_hdr)
            assert r_hosts.status_code == 200
            assert r_hosts.headers.get("X-Total-Count") == "3"
            visible_ips = {h["ip_address"] for h in r_hosts.json()}
            assert visible_ips == {ip_explicit, ip_in_range, ip_in_group}
            assert ip_forbidden not in visible_ips

            assert client.get(f"/api/v1/hosts/{explicit_id}", headers=scoped_hdr).status_code == 200
            assert client.get(f"/api/v1/hosts/{forbidden_id}", headers=scoped_hdr).status_code == 403

            # Dashboard KPI widzi tylko 3 hosty
            dash = client.get("/api/v1/dashboard/summary", headers=scoped_hdr).json()
            assert dash["kpi"]["total_hosts"] == 3

            # Diff (/changes) nie zawiera ip_forbidden i blokuje acknowledge spoza zakresu
            changes_ips = {ev["host_ip"] for ev in client.get("/api/v1/changes?limit=500", headers=scoped_hdr).json()}
            assert ip_forbidden not in changes_ips
            assert client.patch(f"/api/v1/changes/{forbidden_ev_id}/acknowledge", headers=scoped_hdr).status_code == 403

            # Overrides: dozwolony host OK, host spoza zakresu -> 403
            r_ov_ok = client.patch(
                "/api/v1/overrides",
                headers=scoped_hdr,
                json={"entity_type": "host", "entity_id": explicit_id, "custom_label": "Scoped OK"},
            )
            assert r_ov_ok.status_code == 200
            r_ov_forb = client.patch(
                "/api/v1/overrides",
                headers=scoped_hdr,
                json={"entity_type": "host", "entity_id": forbidden_id, "custom_label": "Should fail"},
            )
            assert r_ov_forb.status_code == 403

            # Auto-grupy nie mogą ujawnić technologii tajnego hosta!
            auto_labels = [g["label"] for g in client.get("/api/v1/groups/auto", headers=scoped_hdr).json()["groups"]]
            assert all(forbidden_tech not in lbl for lbl in auto_labels)

            # Skanowanie: dozwolone IP OK, zakazane IP lub zbyt szeroki CIDR -> 403
            assert (
                client.post(
                    "/api/v1/scans/start",
                    headers=scoped_hdr,
                    json={"raw_targets": [ip_explicit], "dry_run": True},
                ).status_code
                == 200
            )
            assert (
                client.post(
                    "/api/v1/scans/start",
                    headers=scoped_hdr,
                    json={"raw_targets": [ip_forbidden], "dry_run": True},
                ).status_code
                == 403
            )
            assert (
                client.post(
                    "/api/v1/scans/start",
                    headers=scoped_hdr,
                    json={"raw_targets": [f"198.51.{octet}.0/24"], "dry_run": True},
                ).status_code
                == 403
            )

            # Eksport JSON stanu i Dry-Run DefectDojo zawierają wyłącznie dozwolone 3 hosty
            exp_hosts = client.get("/api/v1/scans/export?format=json", headers=scoped_hdr).json()["hosts"]
            assert {h["ip_address"] for h in exp_hosts} == {ip_explicit, ip_in_range, ip_in_group}

            dd_dry = client.post(
                "/api/v1/integrations/defectdojo/export",
                headers=scoped_hdr,
                json={"dry_run": True},
            )
            assert dd_dry.status_code == 200
            assert {a["ip_address"] for a in dd_dry.json()["assets"]} == {ip_explicit, ip_in_range, ip_in_group}

            dd_forb = client.post(
                "/api/v1/integrations/defectdojo/export",
                headers=scoped_hdr,
                json={"host_ids": [forbidden_id], "dry_run": True},
            )
            assert dd_forb.status_code == 403

            # 7. Ochrona przed eskalacją uprawnień przez ograniczonego admina
            assert (
                client.patch(
                    f"/api/v1/rbac/users/{scoped_uid}",
                    headers=scoped_hdr,
                    json={"scope_restricted": False},
                ).status_code
                == 403
            )
            assert (
                client.patch(
                    f"/api/v1/groups/{grp_id}",
                    headers=scoped_hdr,
                    json={"filter_rules": {"statuses": ["online"]}},
                ).status_code
                == 403
            )
    finally:
        _cleanup()
