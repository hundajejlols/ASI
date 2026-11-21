#!/usr/bin/env bash
# =============================================================================
# Janus ASI (Attack Surface Intelligence — CBI AGH) — Scenariusz Demo na Żywo dla Jury
#
# Użycie:
#   ./scripts/demo_scenario.sh          # Tryb interaktywny (pauza między krokami)
#   ./scripts/demo_scenario.sh --auto   # Tryb automatyczny (bez czekania na Enter)
#   ./scripts/demo_scenario.sh --step 1 # Uruchom tylko wybrany krok (1, 2 lub 3)
# =============================================================================

set -euo pipefail

export PATH="/Applications/Docker.app/Contents/Resources/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"

API_URL="${API_URL:-http://localhost:8000/api/v1}"
DEMO_CIDR="172.28.0.8/29" # Obejmuje 172.28.0.10 (nginx), .11 (whoami), .12 (staging admin portal)

AUTO_MODE=false
ONLY_STEP=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --auto|-y)
      AUTO_MODE=true
      shift
      ;;
    --step)
      ONLY_STEP="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
RED="\033[0;31m"
RESET="\033[0m"

banner() {
  echo -e "\n${BOLD}${CYAN}=============================================================================${RESET}"
  echo -e "${BOLD}${CYAN}  $1${RESET}"
  echo -e "${BOLD}${CYAN}=============================================================================${RESET}"
}

pause_step() {
  if [[ "$AUTO_MODE" == "false" && -z "$ONLY_STEP" ]]; then
    echo -e "\n${YELLOW}[DEMO] Naciśnij Enter, aby przejść do kolejnego kroku...${RESET}"
    read -r
  fi
}

run_scan_and_wait() {
  local label="$1"
  echo -e "${CYAN}▶ Uruchamianie skanu (${label}) dla zakresu ${DEMO_CIDR}...${RESET}"
  local resp
  resp=$(curl -sS -X POST "${API_URL}/scans/start" \
    -H "Content-Type: application/json" \
    -H "X-Dev-Role: admin" \
    -d "{\"raw_targets\":[\"${DEMO_CIDR}\"],\"window_minutes\":30,\"dry_run\":false}")

  local run_id
  run_id=$(echo "$resp" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
except Exception as e:
    sys.stderr.write(f'Błąd odpowiedzi JSON z /scans/start: {e}\n')
    sys.exit(1)
if 'scan_run_id' not in d:
    sys.stderr.write(f'Błąd API /scans/start: {d}\n')
    sys.exit(1)
print(d['scan_run_id'])
")
  echo -e "  scan_run_id: ${BOLD}${run_id}${RESET}"

  local max_tries=60
  local attempt=0
  while (( attempt < max_tries )); do
    attempt=$((attempt + 1))
    local st
    st=$(curl -sS "${API_URL}/scans/runs/${run_id}" -H "X-Dev-Role: read_only" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" || echo "error")
    if [[ "$st" == "completed" || "$st" == "failed" || "$st" == "paused_window" ]]; then
      echo -e "  status skanu: ${GREEN}${BOLD}${st}${RESET}"
      return 0
    fi
    sleep 2
  done
  echo -e "  ${RED}Przekroczono timeout oczekiwania na zakończenie skanu (${run_id}). Sprawdź logi usługi scanner (docker compose logs scanner).${RESET}" >&2
  return 1
}

print_hosts_table() {
  curl -s "${API_URL}/hosts" -H "X-Dev-Role: read_only" | python3 -c "
import sys, json
hosts = sorted(json.load(sys.stdin), key=lambda x: x['ip_address'])
print(f'  {\"IP\":<14} | {\"STATUS\":<10} | {\"MISSED\":<6} | {\"USŁUGI\":<6} | {\"HOSTNAME / ETYKIETA\"}')
print('  ' + '-' * 72)
for h in hosts:
    lbl = (h.get('override') or {}).get('custom_label') or h.get('hostname') or '-'
    print(f'  {h[\"ip_address\"]:<14} | {h[\"status\"]:<10} | {h[\"missed_scans\"]:<6} | {h[\"open_services_count\"]:<6} | {lbl}')
"
}

step_1() {
  banner "KROK 1: Skanowanie 3 celów w lab_net + Fingerprinting HTTP/TLS + Pasywne Sygnatury"
  docker start asi_lab_nginx asi_lab_whoami asi_lab_staging >/dev/null 2>&1 || true
  sleep 2

  echo -e "${CYAN}▶ Rejestracja zakresu ${DEMO_CIDR} w /api/v1/targets...${RESET}"
  curl -s -X POST "${API_URL}/targets" \
    -H "Content-Type: application/json" \
    -H "X-Dev-Role: add_delete_modify" \
    -d "{\"raw_value\":\"${DEMO_CIDR}\"}" >/dev/null || true

  run_scan_and_wait "Skan #1 — Discovery & Fingerprinting"

  echo -e "\n${BOLD}Wykryte hosty w sieci lab_net:${RESET}"
  print_hosts_table

  echo -e "\n${BOLD}Szczegóły 3. hosta (172.28.0.12 — AGH Internal Staging - Admin Portal, HTTP + HTTPS/TLS):${RESET}"
  curl -s "${API_URL}/hosts" -H "X-Dev-Role: read_only" | python3 -c "
import sys, json, urllib.request
hosts = json.load(sys.stdin)
h12 = next((h for h in hosts if h['ip_address'] == '172.28.0.12'), None)
if not h12:
    print('  Brak hosta 172.28.0.12!')
    sys.exit(0)
req = urllib.request.Request('${API_URL}/hosts/' + h12['id'], headers={'X-Dev-Role': 'read_only'})
detail = json.loads(urllib.request.urlopen(req).read().decode())
for svc in detail['services']:
    fp = svc.get('latest_http_fingerprint') or {}
    print(f'  Port: {svc[\"port\"]}/{svc[\"protocol\"]} ({svc.get(\"service_name\")} | {svc.get(\"product\")} {svc.get(\"version\")})')
    print(f'  URL / Tytuł:     {fp.get(\"url\")} -> {fp.get(\"title\")}')
    if fp.get('tls_subject'):
        print(f'  Certyfikat TLS:  {fp.get(\"tls_subject\")} (self_signed={fp.get(\"tls_is_self_signed\")}, SAN={fp.get(\"tls_san\")})')
    print(f'  is_staging_env:  {fp.get(\"is_staging_env\")} | is_admin_panel: {fp.get(\"is_admin_panel\")}')
    print(f'  Technologie:     {fp.get(\"technologies\")}')
    print(f'  Dopasowane sygnatury pasywne ({len(svc.get(\"signature_matches\", []))}):')
    for m in svc.get('signature_matches', []):
        print(f'    - [{m[\"severity\"].upper()}] {m[\"signature_name\"]} -> {m[\"matched_evidence\"]}')
"
}

step_2() {
  banner "KROK 2: Niestabilny host (missed_scans: 1, 2 -> unstable | 3 -> offline)"
  echo -e "${YELLOW}▶ Zatrzymywanie kontenera asi_lab_whoami (172.28.0.11)...${RESET}"
  docker stop asi_lab_whoami >/dev/null

  for i in 1 2 3; do
    echo ""
    run_scan_and_wait "Skan po awarii #${i} (próg missed_scans = 3)"
    print_hosts_table
  done

  echo -e "\n${BOLD}Ostatnie zdarzenia Diff (GET /api/v1/changes?change_type=host_offline):${RESET}"
  curl -s "${API_URL}/changes?change_type=host_offline&limit=3" -H "X-Dev-Role: read_only" | python3 -c "
import sys, json
for ev in json.load(sys.stdin):
    print(f'  - [{ev[\"change_type\"]}] host={ev[\"host_ip\"]} prev={ev[\"previous_value\"]} -> curr={ev[\"current_value\"]}')
"
}

step_3() {
  banner "KROK 3: Powrót hosta do sieci (host_recovered) + Podgląd DefectDojo Bridge"
  echo -e "${GREEN}▶ Ponowne uruchamianie kontenera asi_lab_whoami (172.28.0.11)...${RESET}"
  docker start asi_lab_whoami >/dev/null
  sleep 2

  run_scan_and_wait "Skan po przywróceniu hosta 172.28.0.11"
  print_hosts_table

  echo -e "\n${BOLD}Zdarzenia powrotu hosta (GET /api/v1/changes?change_type=host_recovered):${RESET}"
  curl -s "${API_URL}/changes?change_type=host_recovered&limit=3" -H "X-Dev-Role: read_only" | python3 -c "
import sys, json
for ev in json.load(sys.stdin):
    print(f'  - [{ev[\"change_type\"]}] host={ev[\"host_ip\"]} prev={ev[\"previous_value\"]} -> curr={ev[\"current_value\"]}')
"

  echo -e "\n${BOLD}Podgląd eksportu DefectDojo API v2 (1 IP = 1 Asset, dry_run=true, only_interesting=true):${RESET}"
  curl -s -X POST "${API_URL}/integrations/defectdojo/export" \
    -H "Content-Type: application/json" \
    -H "X-Dev-Role: modify_read" \
    -d '{"dry_run":true,"only_interesting":true}' | python3 -c "
import sys, json
res = json.load(sys.stdin)
print('  Statystyki:', res.get('stats'))
for asset in res.get('assets', []):
    print(f'  [Asset: {asset[\"product_name\"]} | Org: {asset[\"product_type_name\"]} ({asset[\"product_type_source\"]}) | findings={asset[\"findings_count\"]}]')
    for f in (asset.get('payload') or {}).get('findings', []):
        print(f'    * [{f[\"severity\"]}] {f[\"title\"]} -> tags={f[\"tags\"]}')
"
}

case "$ONLY_STEP" in
  1) step_1 ;;
  2) step_2 ;;
  3) step_3 ;;
  *)
    step_1
    pause_step
    step_2
    pause_step
    step_3
    echo -e "\n${GREEN}${BOLD}✔ Scenariusz demonstracyjny zakończony pomyślnie! Dashboard UI: http://localhost:3000${RESET}"
    ;;
esac
