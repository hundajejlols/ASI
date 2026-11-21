# Janus ASI — Attack Surface Intelligence (CBI AGH)

**Janus ASI** to prototyp inteligentnego pomostu (**middleware / orkiestratora**) pomiędzy narzędziami skanującymi (`nmap`, HTTP/HTTPS fingerprinting, pasywny silnik sygnatur) a platformą **DefectDojo (API v2)**, przygotowany dla **Centrum Bezpieczeństwa Informacji AGH**.

Szczegółowy opis architektury, algorytmu `missed_scans`, szyfrowania `AES-256-GCM` oraz izolacji `asset_overrides` znajduje się w dokumencie **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

---

## 1. Szybki start (Docker Compose)

```bash
cp .env.example .env
# Zalecane przed wdrożeniem: wygeneruj losowy 256-bitowy klucz AES-GCM i ustaw ALLOW_WEAK_ENCRYPTION_KEY=false
python3 -c "import os,base64; print('ENCRYPTION_MASTER_KEY=' + base64.b64encode(os.urandom(32)).decode())"
docker compose up --build -d
```

### Dostępne usługi lokalne
| Usługa | Adres URL | Opis |
| :--- | :--- | :--- |
| **Frontend UI (React + Tailwind)** | **http://localhost:3000** *(oraz `:5173`)* | `Dashboard` (wykres zmian, pora dnia, grupowanie usług), `Hosts` (paginacja + overrides host/service), `Diff` (porównanie 2 skanów + ACK), `Targets & Scans` (adaptacyjny chunker, harmonogramy, re-probe), `Signatures`, `DefectDojo`, `RBAC & Audit` |
| **Backend API (Swagger / OpenAPI)** | **http://localhost:8000/docs** | Interaktywna dokumentacja wszystkich endpointów `/api/v1/*` |
| **Healthcheck API** | **http://localhost:8000/api/v1/health** | Status połączenia z PostgreSQL 16 oraz Redis 7 |

### Testy automatyczne (`go test`, `pytest`, `tsc`)
```bash
# Testy Backendu (FastAPI, AES-256-GCM+AAD, JWT/RBAC, chunker, ingest, CSV ';')
docker exec -e PYTHONPATH=/app asi_backend python3 -m pytest -v -o cache_dir=/tmp/pytest_cache /app/tests/test_asi_core.py

# Testy Frontendu (TypeScript + Vite build)
docker exec asi_frontend sh -c "npx tsc --noEmit && npm run build"

# Testy Skanera Go (uruchamiane automatycznie podczas docker compose build scanner)
docker compose build scanner
```

---

## 2. Scenariusz demonstracyjny na żywo (dla Jury)

W izolowanej sieci Docker `lab_net` (`172.28.0.0/24`) działają **3 bezpieczne kontenery testowe**:
1. `172.28.0.10` (`asi_lab_nginx`) — standardowy serwer `nginx:alpine`.
2. `172.28.0.11` (`asi_lab_whoami`) — serwer `traefik/whoami` (Golang + test ochrony **soft-404** oraz odrzucania fałszywych favicon `text/plain`).
3. `172.28.0.12` (`asi_lab_staging`) — `AGH Internal Staging - Admin Portal` na portach **80 (HTTP)** i **443 (HTTPS z self-signed TLS + SAN DNS/IP)** (`is_staging_env: true`, `is_admin_panel: true`, deterministyczny **Favicon MMH3** `/favicon.ico`, `X-Powered-By: PHP/7.4.33`, `PHPSESSID`, stopka `Powered by LegacyCMS v1.4.2`, ścieżki `/admin` i `/login`).

Aby uruchomić kompletny pokaz (discovery 3 hostów → awaria hosta i przejście `online` → `unstable` → `offline` → powrót `host_recovered` → eksport `dry_run` do DefectDojo):

```bash
./scripts/demo_scenario.sh          # Tryb interaktywny z pauzami na komentarz dla jury
./scripts/demo_scenario.sh --auto   # Tryb ciągły (automatyczny)
```

---

## 3. Uwierzytelnianie JWT i elastyczny model RBAC (4 role + własne role)

System obsługuje **pełne logowanie JWT (`POST /api/v1/auth/login`, hasła `scrypt`)** z dziennikiem `audit_logs` oraz **tworzenie własnych ról RBAC** (`POST /api/v1/rbac/roles`). W trybie demonstracyjnym (`ALLOW_DEV_ROLE_HEADER=true`) dostępny jest dodatkowo przełącznik roli w górnym pasku UI (nagłówek `X-Dev-Role`); wywołania bez JWT i bez `X-Dev-Role` są odrzucane kodem `401 Unauthorized`.

Domyślne konta demo (tabela `users`): `admin / admin123!`, `operator / operator123!`, `analyst / analyst123!`, `viewer / viewer123!`.

| Rola (`rbac_roles`) | Uprawnienia w systemie |
| :--- | :--- |
| `admin` | Pełny dostęp + zarządzanie rolami RBAC i użytkownikami (`/api/v1/rbac/*`), podgląd `audit_logs`, konfiguracja i testowanie DefectDojo (`PUT /api/v1/integrations/defectdojo`, `POST .../test`). |
| `add_delete_modify` | Dodawanie/import/edycja/usuwanie celów, harmonogramów (`/api/v1/schedules`) i sygnatur, uruchamianie/wznawianie/anulowanie skanów, `reprobe-unstable`, formularz ręczny (`/api/v1/scans/manual`) i import CSV/JSON, edycja `asset_overrides`, eksport do DefectDojo. |
| `modify_read` | Odczyt wszystkich danych, porównanie 2 skanów (`/api/v1/scans/compare`), edycja ręcznych nadpisań (`PATCH /api/v1/overrides` dla hostów i usług), potwierdzanie Diff (`PATCH /api/v1/changes/{id}/acknowledge`), edycja sygnatur/harmonogramów/celów, eksport do DefectDojo. |
| `read_only` | Wyłącznie odczyt dashboardu, hostów, odszyfrowanych fingerprintów HTTP, historii zmian (Diff), porównania skanów oraz eksport stanu do plików `CSV` / `JSON`. |

---

## 4. Kluczowe zmienne środowiskowe (`.env`)

| Zmienna | Domyślna wartość (dev) | Opis |
| :--- | :--- | :--- |
| `DATABASE_URL` | `postgresql+psycopg://asi_user:...@postgres:5432/asi_db` | Połączenie SQLAlchemy (`psycopg3`) z bazą PostgreSQL 16 (port zbindowany na `127.0.0.1`) |
| `REDIS_PASSWORD` / `REDIS_URL` | `redis://:<hasło>@redis:6379/0` | Kolejka zadań (`asi:scan:chunks`, `BLMove`) chroniona hasłem i zbindowana na `127.0.0.1` |
| `ENCRYPTION_MASTER_KEY` | 32-bajtowy klucz Base64 | Klucz główny `AES-256-GCM + AAD` (odrzuca zerowy klucz gdy `ALLOW_WEAK_ENCRYPTION_KEY=false`) |
| `JWT_SECRET_KEY` / `ALLOW_DEV_ROLE_HEADER` | losowy sekret / `true` | Sekret podpisywania JWT HS256; ustaw `ALLOW_DEV_ROLE_HEADER=false` na produkcji |
| `SCANNER_INTERNAL_TOKEN` | losowy token | Token uwierzytelniający workery Go w `POST /api/v1/scans/ingest` |
| `SCANNER_CHUNK_WORKERS` / `SCANNER_CONCURRENCY` | `2` / `4` | Równoległe wątki paczek CIDR w workerze Go oraz limit goroutines HTTP wewnątrz paczki (`--scale scanner=3`) |
| `SCANNER_RATE_LIMIT_PPS` / `SCANNER_HTTP_MAX_RPS` | `300` / `20` | Limity pakietów/s (`nmap --max-rate`) oraz zapytań HTTP/s (`token bucket`) |
| `VITE_API_BASE_URL` | `http://localhost:8000/api/v1` | Adres Backend API używany przez aplikację React |

---

## 5. Podpięcie prawdziwej instancji DefectDojo (API v2 — model `1 IP = 1 Asset`)

Kontener `backend` posiada skonfigurowane mapowanie `host.docker.internal:host-gateway`, dzięki czemu z wnętrza Dockera może łączyć się zarówno z DefectDojo uruchomionym lokalnie na hoście, jak i ze zdalną instancją uczelnianą.

Każdy skanowany adres IP trafia do **własnego Assetu (`Product`)** w DefectDojo (`product_name = <IP>`), dzięki czemu administratorzy poszczególnych serwerów mogą otrzymywać osobne uprawnienia RBAC wyłącznie do swoich zasobów.

1. **Wygenerowanie klucza API v2 w DefectDojo:**
   - Zaloguj się do DefectDojo (konto serwisowe z uprawnieniami do tworzenia Produktów/Assetów w docelowym Product Type) → kliknij menu użytkownika w prawym górnym rogu → wybierz **API v2 Key** i skopiuj wygenerowany token.
2. **Konfiguracja i test w Janus ASI UI (`http://localhost:3000` → zakładka *DefectDojo*):**
   - Przełącz rolę RBAC w górnym pasku na `admin`.
   - Wpisz **Base URL**:
     - `http://host.docker.internal:8080` (dla DefectDojo działającego lokalnie na porcie `8080` hosta), lub
     - `https://defectdojo.agh.edu.pl` (dla instancji zewnętrznej).
   - Ustaw **Domyślną Organizację (Product Type)** (np. `AGH Attack Surface` — dla hostów z ustawionym `owner_unit` w `asset_overrides` używane jest `owner_unit`), **Nazwę Engagement (per Asset)** (np. `Janus ASI — Attack Surface`), wklej **Token API v2** i kliknij **Zapisz konfigurację** (token zostanie zaszyfrowany algorytmem `AES-256-GCM`), a następnie kliknij **Test Connection**.
   - W panelu po prawej stronie możesz wyszukać i wybrać konkretne hosty (lub wszystkie), wygenerować podgląd raportu per Asset (`Dry-Run`), a po odznaczeniu `Dry-Run` zsynchronizować każdy IP z osobnym Assetem w DefectDojo API v2 (`POST /api/v2/reimport-scan/` z `auto_create_context=true`, `scan_type="Generic Findings Import"`). Istniejące Assety zachowują organizację ustawioną ręcznie w DefectDojo.
