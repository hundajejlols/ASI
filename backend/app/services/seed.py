"""
Idempotentny seed i migracja bazy uruchamiana przy starcie API:
  - migracja brakujących kolumn/tabel (rbac_roles, custom_role_name, tech_confidence, integrations.*),
  - seed 4 wbudowanych ról RBAC i 4 kont demonstracyjnych (hash scrypt),
  - seed domyślnej grupy local-lab i profilu default-safe-lab (ochrona przed pustą bazą),
  - seed 8 domyślnych bezpiecznych sygnatur pasywnych.
"""

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.security import BUILTIN_ROLE_PERMS_BY_NAME, hash_password
from app.db.models import CustomSignature, RbacRole, ScanProfile, TargetGroup, User

DEFAULT_ROLE_DESCRIPTIONS = {
    "admin": "Pełna administracja: zarządzanie rolami RBAC, użytkownikami, logami audytu i integracją DefectDojo.",
    "add_delete_modify": "Operacje skanowania: cele, uruchamianie/wznawianie skanów, harmonogramy, import/formularz, CRUD sygnatur.",
    "modify_read": "Analityk: odczyt danych, edycja nadpisań (asset_overrides), modyfikacja sygnatur/harmonogramów, eksport DefectDojo.",
    "read_only": "Audytor (tylko odczyt): dashboard, hosty, Diff, przebiegi skanów oraz eksport stanu do CSV/JSON.",
}

DEFAULT_DEMO_USERS = [
    ("admin", "admin@cbi.agh.edu.pl", "admin123!", "admin"),
    ("operator", "operator@cbi.agh.edu.pl", "operator123!", "add_delete_modify"),
    ("analyst", "analyst@cbi.agh.edu.pl", "analyst123!", "modify_read"),
    ("viewer", "viewer@cbi.agh.edu.pl", "viewer123!", "read_only"),
]

DEFAULT_PASSIVE_SIGNATURES = [
    {
        "name": "Exposed X-Powered-By Header",
        "description": "Wykrywa ujawnianie technologii w nagłówku X-Powered-By",
        "severity": "info",
        "match_type": "header",
        "pattern": r"(?i)^X-Powered-By:\s*.+",
        "probe_path": None,
        "expected_status": None,
    },
    {
        "name": "Server Version Disclosure",
        "description": "Wykrywa numer wersji serwera HTTP w nagłówku Server",
        "severity": "info",
        "match_type": "header",
        "pattern": r"(?i)^Server:\s*\S+/\d+\.\d+",
        "probe_path": None,
        "expected_status": None,
    },
    {
        "name": "PHP Session Cookie (PHPSESSID)",
        "description": "Wykrywa obecność ciasteczka sesyjnego PHP",
        "severity": "info",
        "match_type": "cookie",
        "pattern": "PHPSESSID",
        "probe_path": None,
        "expected_status": None,
    },
    {
        "name": "Java Session Cookie (JSESSIONID)",
        "description": "Wykrywa obecność ciasteczka sesyjnego Java/Tomcat",
        "severity": "info",
        "match_type": "cookie",
        "pattern": "JSESSIONID",
        "probe_path": None,
        "expected_status": None,
    },
    {
        "name": "Admin Panel Path (/admin)",
        "description": "Pasywne sprawdzenie GET obecności ścieżki /admin (bez prób logowania)",
        "severity": "medium",
        "match_type": "path_probe",
        "pattern": r"(?i)(admin|dashboard|login)",
        "probe_path": "/admin",
        "expected_status": 200,
    },
    {
        "name": "Login Page Path (/login)",
        "description": "Pasywne sprawdzenie GET obecności strony logowania /login (bez prób logowania)",
        "severity": "low",
        "match_type": "path_probe",
        "pattern": r"(?i)(login|sign in|password)",
        "probe_path": "/login",
        "expected_status": 200,
    },
    {
        "name": "Version Endpoint (/version)",
        "description": "Pasywne sprawdzenie GET ujawniania wersji pod /version",
        "severity": "low",
        "match_type": "path_probe",
        "pattern": r"(?i)(version|build|commit)",
        "probe_path": "/version",
        "expected_status": 200,
    },
    {
        "name": "Footer Version String",
        "description": "Wykrywa informacje o wersji aplikacji/CMS w stopce HTML",
        "severity": "info",
        "match_type": "footer_version",
        "pattern": r"(?i)(powered by|version|ver\.?)\s+[a-z0-9._-]+\s+v?\d+\.\d+(\.\d+)?",
        "probe_path": None,
        "expected_status": None,
    },
    {
        "name": "CMS Generator Version Disclosure",
        "description": "Wykrywa ujawnianie konkretnej wersji CMS (np. WordPress 4.7) w meta tagu generator",
        "severity": "low",
        "match_type": "html_fragment",
        "pattern": r"(?i)<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"'][^\"']+\d+\.\d+[^\"']*[\"']",
        "probe_path": None,
        "expected_status": None,
    },
    {
        "name": "WordPress Login / Setup Endpoint",
        "description": "Pasywne sprawdzenie GET obecności ekranu logowania WordPress (/wp-login.php)",
        "severity": "low",
        "match_type": "path_probe",
        "pattern": r"(?i)(wp-submit|wordpress|user_login)",
        "probe_path": "/wp-login.php",
        "expected_status": 200,
    },
    {
        "name": "Exposed Traefik Dashboard (/dashboard/)",
        "description": "Pasywne sprawdzenie GET niezabezpieczonego panelu Traefik (/dashboard/)",
        "severity": "high",
        "match_type": "path_probe",
        "pattern": r"(?i)traefik",
        "probe_path": "/dashboard/",
        "expected_status": 200,
    },
    {
        "name": "Database Admin Panel (phpMyAdmin / Adminer)",
        "description": "Wykrywa wystawiony panel zarządzania bazą danych (phpMyAdmin lub Adminer)",
        "severity": "high",
        "match_type": "html_fragment",
        "pattern": r"(?i)(phpmyadmin|login\s*-\s*adminer|adminer\.org)",
        "probe_path": None,
        "expected_status": None,
    },
]

EXTRA_SCAN_PROFILES = [
    {
        "name": "agh-web-and-infra",
        "nmap_flags": "-sT -sV --version-light -T4 --max-retries 1",
        "ports": "21,22,25,53,80,81,110,143,443,445,2223,3000,3001,3306,3389,5000,5432,5672,5673,6379,8000,8080,8081,8085,8086,8088,8089,8090,8443,8474,8787,8888,9000,9090,9200,9443,15432,15672,15673,27017",
        "rate_limit_pps": 250,
        "max_concurrency": 4,
        "chunk_cidr_prefix": 24,
        "http_fingerprint_enabled": True,
        "signatures_enabled": True,
    },
    {
        "name": "full-top1000",
        "nmap_flags": "-sT -sV --version-light -T4 --max-retries 1",
        "ports": "top-1000",
        "rate_limit_pps": 300,
        "max_concurrency": 4,
        "chunk_cidr_prefix": 24,
        "http_fingerprint_enabled": True,
        "signatures_enabled": True,
    },
]


def ensure_default_group_and_profile(db: Session) -> tuple[TargetGroup, ScanProfile]:
    """Gwarantuje istnienie domyślnej grupy celów i profilu skanowania nawet na pustej bazie."""
    group = (
        db.execute(select(TargetGroup).where(TargetGroup.name == "local-lab")).scalar_one_or_none()
        or db.execute(select(TargetGroup).limit(1)).scalar_one_or_none()
    )
    if group is None:
        group = TargetGroup(
            name="local-lab",
            description="Izolowana sieć testowa Docker lab_net (172.28.0.0/24)",
            environment="lab",
        )
        db.add(group)
        db.flush()

    profile = (
        db.execute(select(ScanProfile).where(ScanProfile.name == "default-safe-lab")).scalar_one_or_none()
        or db.execute(select(ScanProfile).limit(1)).scalar_one_or_none()
    )
    if profile is None:
        profile = ScanProfile(
            name="default-safe-lab",
            nmap_flags="-sT -sV --version-light -T4 --max-retries 1",
            ports="80,443,8080,8443,22",
            rate_limit_pps=200,
            max_concurrency=4,
            chunk_cidr_prefix=24,
            http_fingerprint_enabled=True,
            signatures_enabled=True,
        )
        db.add(profile)
        db.flush()

    return group, profile


def seed_default_signatures(db: Session) -> int:
    # 1. Idempotentna migracja schematu dla istniejących wolumenów PostgreSQL
    db.execute(text("ALTER TABLE integrations ADD COLUMN IF NOT EXISTS product_name VARCHAR(255)"))
    db.execute(text("ALTER TABLE integrations ADD COLUMN IF NOT EXISTS verify_tls BOOLEAN NOT NULL DEFAULT TRUE"))
    db.execute(
        text(
            "ALTER TABLE http_fingerprints ADD COLUMN IF NOT EXISTS tech_confidence JSONB NOT NULL DEFAULT '{}'::jsonb"
        )
    )
    db.execute(
        text("ALTER TABLE http_fingerprints ADD COLUMN IF NOT EXISTS response_time_ms INTEGER")
    )
    db.execute(
        text("ALTER TABLE http_fingerprints ADD COLUMN IF NOT EXISTS probe_error TEXT")
    )
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS rbac_roles (
                name        VARCHAR(64) PRIMARY KEY,
                description TEXT,
                permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
                is_system   BOOLEAN NOT NULL DEFAULT FALSE,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
    )
    db.execute(
        text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS custom_role_name VARCHAR(64) REFERENCES rbac_roles(name) ON DELETE SET NULL"
        )
    )
    db.commit()

    # 2. Domyślna grupa i profile skanowania (chroni przed pustą bazą)
    ensure_default_group_and_profile(db)
    existing_profiles = set(db.execute(select(ScanProfile.name)).scalars().all())
    for prof_cfg in EXTRA_SCAN_PROFILES:
        if prof_cfg["name"] not in existing_profiles:
            db.add(ScanProfile(**prof_cfg))
    db.commit()

    # 3. Seed 4 wbudowanych ról w rbac_roles
    existing_roles = set(db.execute(select(RbacRole.name)).scalars().all())
    for rname, perms in BUILTIN_ROLE_PERMS_BY_NAME.items():
        if rname not in existing_roles:
            db.add(
                RbacRole(
                    name=rname,
                    description=DEFAULT_ROLE_DESCRIPTIONS.get(rname),
                    permissions=sorted(perms),
                    is_system=True,
                )
            )
    db.commit()

    # 4. Seed 4 kont demonstracyjnych w users (dla logowania JWT /api/v1/auth/login)
    existing_users = set(db.execute(select(User.username)).scalars().all())
    for uname, email, pwd, role_name in DEFAULT_DEMO_USERS:
        if uname not in existing_users:
            db.add(
                User(
                    username=uname,
                    email=email,
                    password_hash=hash_password(pwd),
                    role=role_name,
                    custom_role_name=role_name,
                    is_active=True,
                )
            )
    db.commit()

    # 5. Seed domyślnych bezpiecznych sygnatur pasywnych
    existing_names = set(db.execute(select(CustomSignature.name)).scalars().all())
    inserted = 0
    for sig in DEFAULT_PASSIVE_SIGNATURES:
        if sig["name"] in existing_names:
            continue
        db.add(CustomSignature(is_enabled=True, **sig))
        inserted += 1
    if inserted:
        db.commit()
    return inserted
