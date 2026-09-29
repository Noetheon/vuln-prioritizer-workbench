#!/usr/bin/env bash
# Build the single-container `vpw serve` image and smoke-test local and team mode.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${VPW_SERVE_IMAGE:-vuln-prioritizer-workbench-serve:local}"
port="${VPW_SERVE_SMOKE_PORT:-18765}"
smoke_id="vpw-serve-smoke-$(date +%s)-$$"
local_container="${smoke_id}-local"
team_container="${smoke_id}-team"
volume="${smoke_id}-data"
base_url="http://127.0.0.1:${port}"

cleanup() {
  status=$?
  if [[ "$status" -ne 0 ]]; then
    docker logs "$local_container" 2>&1 | tail -n 40 || true
    docker logs "$team_container" 2>&1 | tail -n 40 || true
  fi
  docker rm -f "$local_container" "$team_container" >/dev/null 2>&1 || true
  docker volume rm -f "$volume" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

if [[ "${VPW_SERVE_SKIP_BUILD:-}" != "1" ]]; then
  docker build --file "$repo_root/backend/Dockerfile" --target serve --tag "$image" "$repo_root"
fi

wait_for_health() {
  for _ in $(seq 1 60); do
    if curl -fsS "$base_url/api/v1/utils/health-check/" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "The Workbench did not become healthy at $base_url." >&2
  return 1
}

json_check() {
  python3 -c "import json, sys; value = json.load(sys.stdin); assert $1, value"
}

echo "Local mode: data volume, migrations, browser app, and backup."
docker run -d --name "$local_container" -p "127.0.0.1:${port}:8765" -v "$volume:/data" "$image" >/dev/null
wait_for_health
curl -fsS "$base_url/api/v1/workbench/status" | json_check 'value["status"] == "ready"'
curl -fsS "$base_url/api/v1/workbench/session" | json_check 'value["auth_mode"] == "local"'
curl -fsS "$base_url/" | grep -q '<div id="root">'
docker exec "$local_container" test -s /data/secret-key
docker exec "$local_container" vpw backup --output /data/smoke-backup.zip
docker rm -f "$local_container" >/dev/null

echo "Team mode: only trusted proxies may name the signed-in user."
# Published-port traffic reaches the container from the Docker bridge gateway.
docker run -d --name "$team_container" -p "127.0.0.1:${port}:8765" -v "$volume:/data" \
  -e AUTH_MODE=proxy \
  -e TRUSTED_PROXY_CIDRS=172.16.0.0/12,192.168.0.0/16,10.0.0.0/8 \
  -e AUTH_PROXY_LOGOUT_URL=/oauth2/sign_out \
  "$image" >/dev/null
wait_for_health
anonymous="$(curl -s -o /dev/null -w '%{http_code}' "$base_url/api/v1/projects/")"
if [[ "$anonymous" != "401" ]]; then
  echo "Expected 401 without a signed-in user, got $anonymous." >&2
  exit 1
fi
curl -fsS -H "Remote-Email: smoke@example.com" -H "Remote-Name: Smoke Test" \
  "$base_url/api/v1/workbench/session" \
  | json_check 'value["user"] == "smoke@example.com" and value["display_name"] == "Smoke Test" and value["logout_url"] == "/oauth2/sign_out"'
# Loopback inside the container is not a trusted proxy, so a spoofed header is refused.
docker exec "$team_container" python -c '
import urllib.error, urllib.request
request = urllib.request.Request(
    "http://127.0.0.1:8765/api/v1/projects/", headers={"Remote-Email": "mallory@example.com"}
)
try:
    urllib.request.urlopen(request, timeout=5)
except urllib.error.HTTPError as exc:
    assert exc.code == 401, exc.code
else:
    raise SystemExit("an untrusted peer asserted a user")
'
docker exec "$team_container" python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/v1/utils/health-check/', timeout=4)"

echo "vpw serve image smoke passed."
