#!/usr/bin/env bash
# Local desktop migration baseline. This checker is read-only: it checks the
# running full Compose stack before a feature moves into the native app.
set -euo pipefail

terminal_url="${VEXA_DESKTOP_TERMINAL_URL:-http://127.0.0.1:13000}"
gateway_url="${VEXA_DESKTOP_GATEWAY_URL:-http://127.0.0.1:18056}"
compose_project="${VEXA_DESKTOP_COMPOSE_PROJECT:-vexa-v012}"
compose_file="${VEXA_DESKTOP_COMPOSE_FILE:-deploy/compose/docker-compose.yml}"

required_services=(
  admin-api agent-api credential-broker flows-api flows-worker gateway mcp
  meeting-api model-proxy postgres redis runtime storage terminal
)

failed=0

green() {
  printf '   Verdict:  GREEN\n'
}

red() {
  printf '   Verdict:  RED — %s\n' "$1"
  failed=1
}

check_http() {
  local name="$1" url="$2" expected="$3" actual
  printf '\n━━ %s ━━\n' "$name"
  printf '   Expected: HTTP %s from %s\n' "$expected" "$url"
  actual="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$url" || true)"
  printf '   Actual:   HTTP %s\n' "${actual:-none}"
  if [ "$actual" = "$expected" ]; then green; else red "endpoint is unavailable"; fi
}

check_services() {
  local rows service status missing=""
  printf '\n━━ Full local service state ━━\n'
  printf '   Expected: every required service is running; health-checked services are healthy\n'
  rows="$(docker compose -p "$compose_project" -f "$compose_file" ps --format json 2>&1 || true)"
  for service in "${required_services[@]}"; do
    status="$(printf '%s\n' "$rows" | SERVICE="$service" python3 -c '
import json, os, sys
for line in sys.stdin:
    try:
        row = json.loads(line)
    except json.JSONDecodeError:
        continue
    if row.get("Service") == os.environ["SERVICE"]:
        print(row.get("State", ""), row.get("Health", ""))
        break
' 2>/dev/null)"
    if [ -z "$status" ]; then
      missing="$missing $service(absent)"
    elif ! printf '%s' "$status" | grep -q '^running'; then
      missing="$missing $service($status)"
    elif printf '%s' "$status" | grep -q 'unhealthy'; then
      missing="$missing $service($status)"
    fi
  done
  printf '   Actual:  %s\n' "${missing:-all required services are running}"
  if [ -z "$missing" ]; then green; else red "service state differs from the full-stack baseline"; fi
}

check_http "Terminal UI" "$terminal_url" "200"
check_http "Gateway health" "${gateway_url%/}/health" "200"
check_services

printf '\n═══ desktop baseline summary ═══\n'
if [ "$failed" -eq 0 ]; then
  printf 'GREEN — local startup baseline holds.\n'
else
  printf 'RED — do not migrate a component until the running-stack failure is understood.\n'
fi

exit "$failed"
