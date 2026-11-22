-- =============================================================================
-- Janus ASI (Attack Surface Intelligence — CBI AGH) - PostgreSQL Schema
-- Obsługuje: RBAC (4 role), harmonogramy i okna czasowe, paczki CIDR,
-- niestabilne hosty (missed_scans), Diff, sygnatury pasywne,
-- niezależne nadpisania ręczne (asset_overrides) oraz Encryption At Rest (BYTEA).
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- -----------------------------------------------------------------------------
-- 1. RBAC & Użytkownicy
-- -----------------------------------------------------------------------------
CREATE TYPE user_role AS ENUM (
    'admin',
    'add_delete_modify',
    'modify_read',
    'read_only'
);

CREATE TABLE rbac_roles (
    name            VARCHAR(64) PRIMARY KEY,
    description     TEXT,
    permissions     JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_system       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username         VARCHAR(64) NOT NULL UNIQUE,
    email            VARCHAR(255) NOT NULL UNIQUE,
    password_hash    TEXT NOT NULL,
    role             user_role NOT NULL DEFAULT 'read_only',
    custom_role_name VARCHAR(64) REFERENCES rbac_roles(name) ON DELETE SET NULL,
    scope_restricted BOOLEAN NOT NULL DEFAULT FALSE,
    allowed_scope    JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    action          VARCHAR(64) NOT NULL,
    resource_type   VARCHAR(64) NOT NULL,
    resource_id     TEXT,
    details         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at DESC);

-- -----------------------------------------------------------------------------
-- 2. Cele skanowania, profile i okna czasowe
-- -----------------------------------------------------------------------------
CREATE TYPE target_type AS ENUM ('ip', 'cidr', 'domain');

CREATE TABLE target_groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(128) NOT NULL UNIQUE,
    description     TEXT,
    environment     VARCHAR(32) NOT NULL DEFAULT 'prod', -- prod, staging, test, lab
    group_type      VARCHAR(16) NOT NULL DEFAULT 'static', -- static | dynamic
    filter_rules    JSONB NOT NULL DEFAULT '{}'::jsonb,    -- reguły grup automatycznych (Smart Groups)
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE targets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id        UUID NOT NULL REFERENCES target_groups(id) ON DELETE CASCADE,
    raw_value       TEXT NOT NULL,                       -- np. 172.28.0.0/24, example.agh.edu.pl
    type            target_type NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (group_id, raw_value)
);

CREATE TABLE scan_profiles (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                        VARCHAR(128) NOT NULL UNIQUE,
    nmap_flags                  TEXT NOT NULL DEFAULT '-sS -sV --version-light -T3',
    ports                       TEXT NOT NULL DEFAULT 'top-1000',
    rate_limit_pps              INT NOT NULL DEFAULT 300 CHECK (rate_limit_pps > 0),
    max_concurrency             INT NOT NULL DEFAULT 4 CHECK (max_concurrency > 0),
    chunk_cidr_prefix           INT NOT NULL DEFAULT 24 CHECK (chunk_cidr_prefix BETWEEN 16 AND 32),
    http_fingerprint_enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    signatures_enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_schedules (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                    VARCHAR(128) NOT NULL UNIQUE,
    target_group_id         UUID NOT NULL REFERENCES target_groups(id) ON DELETE CASCADE,
    profile_id              UUID NOT NULL REFERENCES scan_profiles(id) ON DELETE RESTRICT,
    cron_expression         VARCHAR(64) NOT NULL,        -- np. '0 22 * * *'
    window_start_utc        TIME NOT NULL,               -- początek okna (HH:MM w strefie timezone, np. '22:00:00')
    window_end_utc          TIME NOT NULL,               -- koniec okna (HH:MM w strefie timezone, np. '06:00:00'; obsługuje północ)
    timezone                VARCHAR(64) NOT NULL DEFAULT 'Europe/Warsaw',
    missed_scans_threshold  INT NOT NULL DEFAULT 3 CHECK (missed_scans_threshold >= 1),
    is_enabled              BOOLEAN NOT NULL DEFAULT TRUE,
    created_by              UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 3. Przebiegi skanów (Scan Runs) i paczki CIDR (Chunks) - Pause / Resume
-- -----------------------------------------------------------------------------
CREATE TYPE scan_run_status AS ENUM (
    'queued',
    'running',
    'paused_window',
    'completed',
    'failed',
    'cancelled'
);

CREATE TYPE scan_chunk_status AS ENUM (
    'pending',
    'in_progress',
    'completed',
    'requeued_window',
    'failed'
);

CREATE TABLE scan_runs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    schedule_id         UUID REFERENCES scan_schedules(id) ON DELETE SET NULL,
    target_group_id     UUID NOT NULL REFERENCES target_groups(id) ON DELETE CASCADE,
    profile_id          UUID NOT NULL REFERENCES scan_profiles(id) ON DELETE RESTRICT,
    status              scan_run_status NOT NULL DEFAULT 'queued',
    scanned_ports       TEXT,                            -- efektywna lista portów tego przebiegu (ochrona przed zamykaniem nieskanowanych portów)
    window_deadline_at  TIMESTAMPTZ,                     -- twardy deadline bieżącego okna czasowego
    total_chunks        INT NOT NULL DEFAULT 0,
    completed_chunks    INT NOT NULL DEFAULT 0,
    started_at          TIMESTAMPTZ,
    paused_at           TIMESTAMPTZ,
    finished_at         TIMESTAMPTZ,
    triggered_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_chunks (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id         UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    target_cidr         TEXT NOT NULL,                   -- np. paczka /24 wydzielona z /16
    status              scan_chunk_status NOT NULL DEFAULT 'pending',
    worker_id           VARCHAR(64),
    attempts            INT NOT NULL DEFAULT 0,
    hosts_discovered    INT NOT NULL DEFAULT 0,
    started_at          TIMESTAMPTZ,
    finished_at         TIMESTAMPTZ,
    error_message       TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_chunks_run_status ON scan_chunks (scan_run_id, status);

-- -----------------------------------------------------------------------------
-- 4. Zasoby (Hosts, Services, HTTP Fingerprints) + obsługa niestabilnych hostów
-- -----------------------------------------------------------------------------
CREATE TYPE host_status AS ENUM ('online', 'unstable', 'offline', 'archived');

CREATE TABLE hosts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address          INET NOT NULL UNIQUE,
    hostname            TEXT,
    status              host_status NOT NULL DEFAULT 'online',
    missed_scans        INT NOT NULL DEFAULT 0 CHECK (missed_scans >= 0),
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_scan_run_id    UUID REFERENCES scan_runs(id) ON DELETE SET NULL
);

CREATE INDEX idx_hosts_status ON hosts (status);

CREATE TABLE services (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id             UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port                INT NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol            VARCHAR(8) NOT NULL DEFAULT 'tcp',
    state               VARCHAR(16) NOT NULL DEFAULT 'open',
    service_name        VARCHAR(64),
    product             VARCHAR(128),
    version             VARCHAR(128),
    banner              TEXT,
    missed_scans        INT NOT NULL DEFAULT 0 CHECK (missed_scans >= 0),
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (host_id, port, protocol)
);

CREATE INDEX idx_services_host_id ON services (host_id);

CREATE TABLE http_fingerprints (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id          UUID NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    scan_run_id         UUID REFERENCES scan_runs(id) ON DELETE SET NULL,
    url                 TEXT NOT NULL,
    scheme              VARCHAR(8) NOT NULL,             -- http / https
    status_code         INT,
    response_time_ms    INT,                             -- czas odpowiedzi HTTP w ms (detekcja latencji / degradacji)
    probe_error         TEXT,                            -- opcjonalny błąd sondy HTTP (np. http_timeout, connection_reset)
    title               TEXT,
    redirect_chain      JSONB NOT NULL DEFAULT '[]'::jsonb,
    headers_encrypted   BYTEA,                           -- AES-256-GCM zaszyfrowany JSON nagłówków HTTP
    cookies_encrypted   BYTEA,                           -- AES-256-GCM zaszyfrowany JSON nazw/danych ciasteczek
    favicon_mmh3_hash   VARCHAR(64),
    tls_subject         TEXT,
    tls_issuer          TEXT,
    tls_not_after       TIMESTAMPTZ,
    tls_san             JSONB NOT NULL DEFAULT '[]'::jsonb,
    technologies        JSONB NOT NULL DEFAULT '[]'::jsonb, -- wykryte CMS/tech/IoT
    tech_confidence     JSONB NOT NULL DEFAULT '{}'::jsonb, -- pewność detekcji (high/medium/low)
    is_admin_panel      BOOLEAN NOT NULL DEFAULT FALSE,
    is_staging_env      BOOLEAN NOT NULL DEFAULT FALSE,
    captured_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_http_fp_service_captured ON http_fingerprints (service_id, captured_at DESC);

-- -----------------------------------------------------------------------------
-- 5. Własne bezpieczne sygnatury (Custom Signatures - wyłącznie pasywne)
-- -----------------------------------------------------------------------------
CREATE TYPE signature_match_type AS ENUM (
    'header',
    'cookie',
    'favicon_hash',
    'html_fragment',
    'path_probe',
    'footer_version'
);

CREATE TYPE finding_severity AS ENUM ('info', 'low', 'medium', 'high', 'critical');

CREATE TABLE custom_signatures (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(128) NOT NULL UNIQUE,
    description         TEXT,
    severity            finding_severity NOT NULL DEFAULT 'info',
    match_type          signature_match_type NOT NULL,
    pattern             TEXT NOT NULL,                   -- regex / exact value / mmh3 hash
    probe_path          TEXT,                            -- np. '/login', '/admin', '/version' (tylko GET/HEAD)
    expected_status     INT,
    is_enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE signature_matches (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id         UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    service_id          UUID NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    signature_id        UUID NOT NULL REFERENCES custom_signatures(id) ON DELETE CASCADE,
    matched_evidence    TEXT,
    matched_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 6. Analiza zmian (Diff) między kolejnymi skanami
-- -----------------------------------------------------------------------------
CREATE TYPE change_event_type AS ENUM (
    'host_new',
    'host_offline',
    'host_recovered',
    'service_new',
    'service_closed',
    'service_changed',
    'tls_changed',
    'tech_changed',
    'signature_matched'
);

CREATE TABLE change_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id         UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    host_id             UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    service_id          UUID REFERENCES services(id) ON DELETE SET NULL,
    change_type         change_event_type NOT NULL,
    severity            finding_severity NOT NULL DEFAULT 'info',
    previous_value      JSONB,
    current_value       JSONB,
    acknowledged        BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    detected_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_change_events_run ON change_events (scan_run_id, detected_at DESC);

-- -----------------------------------------------------------------------------
-- 7. Ręczne nadpisania (asset_overrides) - NIEZALEŻNE od skanera + AES-256-GCM
-- Kolejne skany nigdy nie modyfikują tej tabeli!
-- -----------------------------------------------------------------------------
CREATE TYPE override_entity_type AS ENUM ('host', 'service');

CREATE TABLE asset_overrides (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type         override_entity_type NOT NULL,
    entity_id           UUID NOT NULL,
    custom_label        VARCHAR(128),
    owner_unit          VARCHAR(128),                    -- np. jednostka / wydział AGH
    criticality         finding_severity,
    tags                JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_false_positive   BOOLEAN NOT NULL DEFAULT FALSE,
    is_ignored          BOOLEAN NOT NULL DEFAULT FALSE,
    notes_encrypted     BYTEA,                           -- AES-256-GCM: [ver(1B)|nonce(12B)|ct+tag]
    updated_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (entity_type, entity_id)
);

-- -----------------------------------------------------------------------------
-- 8. Integracje (DefectDojo API v2) - klucze szyfrowane AES-256-GCM
-- -----------------------------------------------------------------------------
CREATE TABLE integrations (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                    VARCHAR(128) NOT NULL UNIQUE,
    provider                VARCHAR(32) NOT NULL DEFAULT 'defectdojo',
    base_url                TEXT NOT NULL,
    api_token_encrypted     BYTEA NOT NULL,              -- AES-256-GCM: [ver(1B)|nonce(12B)|ct+tag]
    product_type_name       VARCHAR(255) NOT NULL DEFAULT 'AGH Attack Surface',
    engagement_name         VARCHAR(255) NOT NULL DEFAULT 'Janus ASI — Attack Surface',
    verify_tls              BOOLEAN NOT NULL DEFAULT TRUE,
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    updated_by              UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE defectdojo_exports (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id          UUID NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
    change_event_id         UUID REFERENCES change_events(id) ON DELETE SET NULL,
    host_id                 UUID REFERENCES hosts(id) ON DELETE SET NULL,
    service_id              UUID REFERENCES services(id) ON DELETE SET NULL,
    product_name            VARCHAR(255),                -- nazwa Assetu (Product) w DefectDojo = adres IP
    defectdojo_product_id   INT,
    defectdojo_finding_id   INT,
    status                  VARCHAR(32) NOT NULL DEFAULT 'exported',
    error_message           TEXT,
    exported_by             UUID REFERENCES users(id) ON DELETE SET NULL,
    exported_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 8. Pasywny AI Security Agent (OpenRouter — tylko do odczytu / alertowanie)
-- -----------------------------------------------------------------------------
CREATE TABLE ai_agent_configs (
    id                      VARCHAR(32) PRIMARY KEY DEFAULT 'default',
    provider                VARCHAR(32) NOT NULL DEFAULT 'openrouter',
    base_url                TEXT NOT NULL DEFAULT 'https://openrouter.ai/api/v1',
    model_name              VARCHAR(128) NOT NULL DEFAULT 'google/gemini-2.5-flash',
    api_key_encrypted       BYTEA NOT NULL,              -- AES-256-GCM + AAD (nigdy nie zwracany w API)
    auto_analyze_after_scan BOOLEAN NOT NULL DEFAULT TRUE,
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ai_alerts (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id                 UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    scan_run_id             UUID REFERENCES scan_runs(id) ON DELETE SET NULL,
    urgency                 VARCHAR(16) NOT NULL DEFAULT 'safe', -- critical | high | medium | low | safe
    requires_admin_alert    BOOLEAN NOT NULL DEFAULT FALSE,
    title                   VARCHAR(255) NOT NULL,
    affected_software       JSONB NOT NULL DEFAULT '[]'::jsonb,
    cves                    JSONB NOT NULL DEFAULT '[]'::jsonb,
    summary                 TEXT NOT NULL,
    admin_alert_message     TEXT,
    remediation             TEXT,
    analysis_source         VARCHAR(128) NOT NULL DEFAULT 'openrouter',
    acknowledged            BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_at         TIMESTAMPTZ,
    acknowledged_by         VARCHAR(64),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ai_alerts_host_created ON ai_alerts (host_id, created_at DESC);
CREATE INDEX idx_ai_alerts_urgency ON ai_alerts (requires_admin_alert, acknowledged, created_at DESC);

-- -----------------------------------------------------------------------------
-- Dane startowe (Seed): domyślny profil skanowania i grupa lab_net
-- -----------------------------------------------------------------------------
INSERT INTO scan_profiles (name, nmap_flags, ports, rate_limit_pps, max_concurrency, chunk_cidr_prefix)
VALUES ('default-safe-lab', '-sT -sV --version-light -T4 --max-retries 1', '80,443,8080,8443,22', 200, 4, 24)
ON CONFLICT (name) DO NOTHING;

INSERT INTO target_groups (name, description, environment)
VALUES ('local-lab', 'Izolowana sieć testowa Docker lab_net (172.28.0.0/24)', 'lab')
ON CONFLICT (name) DO NOTHING;

-- Domyślne bezpieczne sygnatury pasywne (bez prób logowania i exploitów)
INSERT INTO custom_signatures (name, description, severity, match_type, pattern, probe_path, expected_status, is_enabled)
VALUES
    ('Exposed X-Powered-By Header', 'Wykrywa ujawnianie technologii w nagłówku X-Powered-By', 'info', 'header', '(?i)^X-Powered-By:\s*.+', NULL, NULL, TRUE),
    ('Server Version Disclosure', 'Wykrywa numer wersji serwera HTTP w nagłówku Server', 'info', 'header', '(?i)^Server:\s*\S+/\d+\.\d+', NULL, NULL, TRUE),
    ('PHP Session Cookie (PHPSESSID)', 'Wykrywa obecność ciasteczka sesyjnego PHP', 'info', 'cookie', 'PHPSESSID', NULL, NULL, TRUE),
    ('Java Session Cookie (JSESSIONID)', 'Wykrywa obecność ciasteczka sesyjnego Java/Tomcat', 'info', 'cookie', 'JSESSIONID', NULL, NULL, TRUE),
    ('Admin Panel Path (/admin)', 'Pasywne sprawdzenie GET obecności ścieżki /admin (bez prób logowania)', 'medium', 'path_probe', '(?i)(admin|dashboard|login)', '/admin', 200, TRUE),
    ('Login Page Path (/login)', 'Pasywne sprawdzenie GET obecności strony logowania /login (bez prób logowania)', 'low', 'path_probe', '(?i)(login|sign in|password)', '/login', 200, TRUE),
    ('Version Endpoint (/version)', 'Pasywne sprawdzenie GET ujawniania wersji pod /version', 'low', 'path_probe', '(?i)(version|build|commit)', '/version', 200, TRUE),
    ('Footer Version String', 'Wykrywa informacje o wersji aplikacji/CMS w stopce HTML', 'info', 'footer_version', '(?i)(powered by|version|ver\.?)\s+[a-z0-9._-]+\s+v?\d+\.\d+(\.\d+)?', NULL, NULL, TRUE)
ON CONFLICT (name) DO NOTHING;
