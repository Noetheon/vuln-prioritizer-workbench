#!/usr/bin/env bash
# Start the team-mode reference deployment in examples/team-mode and check the
# whole sign-in chain from outside: Caddy, Authelia, and the Workbench in proxy
# mode. Uses the image from `make docker-serve-smoke` and builds it if missing.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${VPW_SERVE_IMAGE:-vuln-prioritizer-workbench-serve:local}"
project="vpw-team-example-$$"
work="$(mktemp -d)"
workbench="https://workbench.example.test"
alice_password="alice-$(openssl rand -hex 12)"
bob_password="bob-$(openssl rand -hex 12)"

compose() {
  VPW_IMAGE="$image" docker compose --project-directory "$work" --project-name "$project" \
    --file "$work/compose.yml" "$@"
}

cleanup() {
  status=$?
  if [[ "$status" -ne 0 ]]; then
    compose ps --all || true
    compose logs --no-color --tail 60 || true
  fi
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

# curl against Caddy on 127.0.0.1:443 under the example's host names, trusting
# only Caddy's local CA.
request() {
  curl --noproxy '*' --silent --show-error --cacert "$work/root.crt" \
    --resolve workbench.example.test:443:127.0.0.1 \
    --resolve auth.example.test:443:127.0.0.1 "$@"
}

status_of() {
  request --output /dev/null --write-out '%{http_code}' "$@"
}

expect_status() {
  local expected="$1" description="$2"
  shift 2
  local actual
  actual="$(status_of "$@")"
  [[ "$actual" == "$expected" ]] || fail "$description: expected HTTP $expected, got $actual"
  echo "ok - $description (HTTP $actual)"
}

json_check() {
  python3 -c "import json, sys; value = json.load(sys.stdin); assert $1, value"
}

if ! docker image inspect "$image" >/dev/null 2>&1; then
  docker build --file "$repo_root/backend/Dockerfile" --target serve --tag "$image" "$repo_root"
fi

# Run a copy, so the generated secrets and users never land in the checkout.
cp -R "$repo_root/examples/team-mode/." "$work/"
VPW_EXAMPLE_PASSWORD="$alice_password" "$work/setup.sh" alice alice@example.test "Alice Example"
VPW_EXAMPLE_PASSWORD="$bob_password" "$work/setup.sh" bob bob@example.test "Bob Outsider" contractors

compose up --detach --wait --wait-timeout 240

for _ in $(seq 1 30); do
  compose cp caddy:/data/caddy/pki/authorities/local/root.crt "$work/root.crt" >/dev/null 2>&1 && break
  sleep 1
done
[[ -s "$work/root.crt" ]] || fail "Caddy did not create its local CA."
for _ in $(seq 1 30); do
  [[ "$(status_of --user "alice:$alice_password" "$workbench/api/v1/workbench/session" || true)" == 200 ]] && break
  sleep 2
done

echo "Without a sign-in, nothing reaches the Workbench."
expect_status 401 "API request without a sign-in" \
  --header "Accept: application/json" "$workbench/api/v1/projects/"
expect_status 401 "forged identity header without a sign-in" \
  --header "Accept: application/json" --header "Remote-Email: alice@example.test" \
  "$workbench/api/v1/projects/"
redirect="$(request --output /dev/null --write-out '%{http_code} %{redirect_url}' \
  --header "Accept: text/html" "$workbench/")"
[[ "$redirect" == "302 https://auth.example.test/"* ]] ||
  fail "browser request without a sign-in: expected a redirect to the portal, got $redirect"
echo "ok - browser request without a sign-in is sent to the portal"

echo "A signed-in user reaches the Workbench under their own name."
request --user "alice:$alice_password" "$workbench/api/v1/workbench/session" |
  json_check 'value["auth_mode"] == "proxy" and value["user"] == "alice@example.test" and value["display_name"] == "Alice Example" and value["logout_url"] == "https://auth.example.test/logout"'
echo "ok - session names alice"
request --user "alice:$alice_password" \
  --header "Remote-Email: mallory@example.test" --header "Remote-Name: Mallory" \
  "$workbench/api/v1/workbench/session" |
  json_check 'value["user"] == "alice@example.test" and value["display_name"] == "Alice Example"'
echo "ok - identity headers sent by the client are replaced by the proxy"
expect_status 403 "signed-in user outside the workbench group" \
  --user "bob:$bob_password" --header "Accept: application/json" "$workbench/api/v1/projects/"

echo "Writes work from the Workbench's own origin only."
request --user "alice:$alice_password" --header "Origin: $workbench" \
  --header "Content-Type: application/json" --data '{"name": "Team mode example"}' \
  "$workbench/api/v1/projects/" |
  json_check 'value["name"] == "Team mode example"'
echo "ok - same-origin write"
expect_status 403 "cross-site write" \
  --user "alice:$alice_password" --header "Origin: https://other.example" \
  --header "Content-Type: application/json" --data '{"name": "Cross-site"}' \
  "$workbench/api/v1/projects/"

echo "Live workflow updates pass through the proxy as WebSockets."
python3 - "$work/root.crt" "alice:$alice_password" <<'PY'
import base64
import os
import socket
import ssl
import sys
import uuid

ca_file, credentials = sys.argv[1], sys.argv[2]
host = "workbench.example.test"
context = ssl.create_default_context(cafile=ca_file)


def handshake(authorization: str | None) -> bytes:
    headers = [
        f"GET /api/v1/workflows/{uuid.uuid4()}/stream HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}",
        "Sec-WebSocket-Version: 13",
        f"Origin: https://{host}",
        "Accept: application/json",
    ]
    if authorization:
        headers.append(f"Authorization: {authorization}")
    with socket.create_connection(("127.0.0.1", 443), timeout=15) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())
            received = b""
            while b"Workflow not found" not in received:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                received += chunk
                if not received.startswith(b"HTTP/1.1 101"):
                    break
            return received


anonymous = handshake(None)
assert anonymous.startswith(b"HTTP/1.1 401"), anonymous[:80]
basic = base64.b64encode(credentials.encode()).decode()
signed_in = handshake(f"Basic {basic}")
assert signed_in.startswith(b"HTTP/1.1 101"), signed_in[:80]
assert b"Workflow not found" in signed_in, signed_in[:200]
PY
echo "ok - WebSocket upgrade needs a sign-in and then reaches the Workbench"

echo "Requests that bypass Caddy cannot name a user."
workbench_container="$(compose ps --quiet workbench)"
workbench_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$workbench_container")"
direct="$(curl --noproxy '*' --silent --output /dev/null --write-out '%{http_code}' \
  --header "Host: workbench.example.test" --header "Remote-Email: alice@example.test" \
  "http://$workbench_ip:8765/api/v1/projects/")"
[[ "$direct" == 401 ]] || fail "direct request with a forged header: expected HTTP 401, got $direct"
echo "ok - direct request with a forged header (HTTP 401)"

echo "Team-mode example smoke passed."
