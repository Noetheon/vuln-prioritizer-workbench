#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

COMPOSE_FILES=(-f compose.yml -f compose.override.yml)
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-vpw-local-workbench}"
export WORKBENCH_DB_VOLUME="${WORKBENCH_DB_VOLUME:-${COMPOSE_PROJECT_NAME}-db-data}"
export WORKBENCH_IMPORT_UPLOADS_VOLUME="${WORKBENCH_IMPORT_UPLOADS_VOLUME:-${COMPOSE_PROJECT_NAME}-import-uploads}"
export WORKBENCH_REPORTS_VOLUME="${WORKBENCH_REPORTS_VOLUME:-${COMPOSE_PROJECT_NAME}-reports}"
export WORKBENCH_PROVIDER_SNAPSHOTS_VOLUME="${WORKBENCH_PROVIDER_SNAPSHOTS_VOLUME:-${COMPOSE_PROJECT_NAME}-provider-snapshots}"
export WORKBENCH_PROVIDER_CACHE_VOLUME="${WORKBENCH_PROVIDER_CACHE_VOLUME:-${COMPOSE_PROJECT_NAME}-provider-cache}"

compose() {
  docker compose "${COMPOSE_FILES[@]}" "$@"
}

usage() {
  cat <<'EOF'
Usage:
  scripts/launch-workbench.sh [start|stop|status|logs|smoke|reset|update|diagnostics]

Commands:
  start        Prepare .env when needed, build images, start db/backend/worker/frontend.
  stop         Stop the local Workbench containers, keeping data volumes.
  status       Show Docker Compose service status.
  logs         Follow recent service logs.
  smoke        Run the Docker quickstart API smoke test against the running backend.
  reset        Stop containers and delete this Workbench project's Docker volumes.
  update       Fast-forward git when clean, then rebuild and start the current checkout.
  diagnostics  Create a redacted diagnostics bundle under diagnostics/.

Environment overrides:
  DOCKER_DEMO_FRONTEND_PORT=15174
  DOCKER_DEMO_BACKEND_PORT=18080
  COMPOSE_PROJECT_NAME=vpw-local-workbench
  VPW_OPEN_BROWSER=0
  VPW_ASSUME_YES=1
EOF
}

require_command() {
  local command_name="$1"
  local install_hint="$2"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required command: $command_name" >&2
    echo "$install_hint" >&2
    exit 1
  fi
}

check_docker() {
  require_command docker "Install Docker Desktop or Docker Engine with the Compose plugin, then rerun this launcher."
  if ! docker compose version >/dev/null 2>&1; then
    echo "Docker Compose plugin is not available. Install/update Docker Desktop or Docker Engine Compose." >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "Docker is installed but not running. Start Docker, then rerun this launcher." >&2
    exit 1
  fi
}

random_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    printf 'local-workbench-%s-%s-%s\n' "$(date +%s)" "$RANDOM" "$RANDOM"
  fi
}

ensure_env_file() {
  if [[ -f .env ]]; then
    return
  fi
  if [[ ! -f .env.example ]]; then
    echo ".env is missing and .env.example was not found." >&2
    exit 1
  fi

  local secret_key
  local postgres_password
  local tmp_env
  secret_key="$(random_secret)"
  postgres_password="$(random_secret)"
  tmp_env="$(mktemp)"

  awk \
    -v secret_key="$secret_key" \
    -v postgres_password="$postgres_password" \
    '
      /^SECRET_KEY=/ { $0 = "SECRET_KEY=" secret_key }
      /^POSTGRES_PASSWORD=/ { $0 = "POSTGRES_PASSWORD=" postgres_password }
      /^DEMO_PROVIDER_SNAPSHOT_ENABLED=/ { $0 = "DEMO_PROVIDER_SNAPSHOT_ENABLED=true" }
      /^DEMO_WORKSPACE_ENABLED=/ { $0 = "DEMO_WORKSPACE_ENABLED=true" }
      { print }
    ' .env.example >"$tmp_env"
  mv "$tmp_env" .env
  echo "Created local .env from .env.example."
}

port_is_busy() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  elif command -v nc >/dev/null 2>&1; then
    nc -z 127.0.0.1 "$port" >/dev/null 2>&1
  else
    (exec 3<>"/dev/tcp/127.0.0.1/$port") >/dev/null 2>&1
  fi
}

choose_port() {
  local env_name="$1"
  local preferred="$2"
  local fallback_start="$3"
  local requested="${!env_name-}"
  local port

  if [[ -n "$requested" ]]; then
    if port_is_busy "$requested"; then
      echo "Configured $env_name=$requested is already in use." >&2
      exit 1
    fi
    printf '%s\n' "$requested"
    return
  fi

  for port in "$preferred" "$fallback_start"; do
    if ! port_is_busy "$port"; then
      printf '%s\n' "$port"
      return
    fi
  done

  port="$fallback_start"
  while [[ "$port" -lt $((fallback_start + 100)) ]]; do
    if ! port_is_busy "$port"; then
      printf '%s\n' "$port"
      return
    fi
    port=$((port + 1))
  done

  echo "No free local port found near $preferred or $fallback_start." >&2
  exit 1
}

published_port() {
  local service="$1"
  local container_port="$2"
  compose port "$service" "$container_port" 2>/dev/null | tail -n 1 | sed -E 's/.*:([0-9]+)$/\1/'
}

service_is_running() {
  local service="$1"
  compose ps --services --status running 2>/dev/null | grep -qx "$service"
}

running_frontend_port() {
  if service_is_running frontend; then
    published_port frontend 8080
  fi
}

running_backend_port() {
  if service_is_running backend; then
    published_port backend 8000
  fi
}

configure_ports_for_start() {
  local existing_frontend_port
  local existing_backend_port
  existing_frontend_port="$(running_frontend_port || true)"
  existing_backend_port="$(running_backend_port || true)"

  if [[ -n "$existing_frontend_port" && -n "$existing_backend_port" ]]; then
    export DOCKER_DEMO_FRONTEND_PORT="$existing_frontend_port"
    export DOCKER_DEMO_BACKEND_PORT="$existing_backend_port"
    return
  fi

  export DOCKER_DEMO_FRONTEND_PORT
  export DOCKER_DEMO_BACKEND_PORT
  DOCKER_DEMO_FRONTEND_PORT="$(choose_port DOCKER_DEMO_FRONTEND_PORT 5173 15174)"
  DOCKER_DEMO_BACKEND_PORT="$(choose_port DOCKER_DEMO_BACKEND_PORT 8000 18080)"
}

configure_runtime_env() {
  export FRONTEND_HOST="http://localhost:${DOCKER_DEMO_FRONTEND_PORT}"
  export BACKEND_CORS_ORIGINS="http://localhost,http://localhost:${DOCKER_DEMO_FRONTEND_PORT},http://127.0.0.1:${DOCKER_DEMO_FRONTEND_PORT}"
  export VITE_API_URL=""
}

wait_for_url() {
  local label="$1"
  local url="$2"
  local expected="${3:-}"
  local attempt
  local response

  for attempt in $(seq 1 60); do
    if response="$(curl -fsS --max-time 3 "$url" 2>/dev/null)"; then
      if [[ -z "$expected" || "$response" == "$expected" ]]; then
        return
      fi
    fi
    sleep 2
  done

  echo "$label did not become ready at $url." >&2
  compose ps >&2 || true
  compose logs --no-color --tail=120 backend frontend worker db >&2 || true
  exit 1
}

open_frontend() {
  local url="$1"
  if [[ "${VPW_OPEN_BROWSER:-1}" == "0" ]]; then
    return
  fi
  if command -v open >/dev/null 2>&1; then
    open "$url" >/dev/null 2>&1 || true
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 || true
  fi
}

print_urls() {
  local frontend_url="http://127.0.0.1:${DOCKER_DEMO_FRONTEND_PORT}"
  local backend_health_url="http://127.0.0.1:${DOCKER_DEMO_BACKEND_PORT}/api/v1/utils/health-check/"

  echo
  echo "Vuln Prioritizer Workbench is running."
  echo "Frontend:       $frontend_url"
  echo "Backend health: $backend_health_url"
  echo
  echo "Stop it with:   scripts/launch-workbench.sh stop"
}

start_workbench() {
  check_docker
  require_command curl "Install curl or use Docker Compose manually."
  ensure_env_file
  configure_ports_for_start
  configure_runtime_env

  echo "Starting Vuln Prioritizer Workbench with Docker Compose..."
  echo "Compose project: $COMPOSE_PROJECT_NAME"
  echo "Frontend port:   $DOCKER_DEMO_FRONTEND_PORT"
  echo "Backend port:    $DOCKER_DEMO_BACKEND_PORT"

  compose up -d --build backend frontend worker

  wait_for_url "Backend health" "http://127.0.0.1:${DOCKER_DEMO_BACKEND_PORT}/api/v1/utils/health-check/" "true"
  wait_for_url "Frontend" "http://127.0.0.1:${DOCKER_DEMO_FRONTEND_PORT}/"
  print_urls
  open_frontend "http://127.0.0.1:${DOCKER_DEMO_FRONTEND_PORT}"
}

stop_workbench() {
  check_docker
  compose down --remove-orphans
}

status_workbench() {
  check_docker
  compose ps
}

logs_workbench() {
  check_docker
  compose logs -f --tail=200 backend frontend worker db
}

confirm_reset() {
  if [[ "${VPW_ASSUME_YES:-0}" == "1" ]]; then
    return
  fi
  if [[ ! -t 0 ]]; then
    echo "Reset requires confirmation. Rerun with VPW_ASSUME_YES=1 to confirm non-interactively." >&2
    exit 1
  fi
  echo "This will delete Docker volumes for Compose project '$COMPOSE_PROJECT_NAME'."
  echo "Uploaded imports, generated reports, provider cache, and the local database will be removed."
  read -r -p "Type RESET to continue: " confirmation
  if [[ "$confirmation" != "RESET" ]]; then
    echo "Reset cancelled."
    exit 0
  fi
}

reset_workbench() {
  check_docker
  confirm_reset
  compose down -v --remove-orphans
  echo "Deleted containers and volumes for Compose project '$COMPOSE_PROJECT_NAME'."
}

update_workbench() {
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if [[ -n "$(git status --short)" ]]; then
      echo "Working tree has local changes; skipping git pull."
      git status --short
    elif git rev-parse --abbrev-ref --symbolic-full-name '@{u}' >/dev/null 2>&1; then
      git pull --ff-only
    else
      echo "No upstream branch configured; skipping git pull."
    fi
  else
    echo "Not a git checkout; skipping git pull."
  fi
  start_workbench
}

diagnostics_timestamp() {
  date -u +%Y%m%dT%H%M%SZ
}

redact_file() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    return
  fi
  sed -E -i.bak \
    -e 's/((secret|password|token|api[_-]?key)[A-Za-z0-9_ .:-]*[=:][[:space:]]*)[^[:space:]",]+/\1[REDACTED]/Ig' \
    -e 's/(Bearer )[A-Za-z0-9._~+\/=-]+/\1[REDACTED]/g' \
    "$file"
  rm -f "${file}.bak"
}

write_command_output() {
  local output_file="$1"
  shift
  {
    printf '$'
    printf ' %q' "$@"
    printf '\n\n'
    "$@"
  } >"$output_file" 2>&1 || true
  redact_file "$output_file"
}

write_url_output() {
  local output_file="$1"
  local url="$2"
  if ! command -v curl >/dev/null 2>&1; then
    printf 'curl is not installed; skipped %s\n' "$url" >"$output_file"
    return
  fi
  {
    printf 'GET %s\n\n' "$url"
    curl -fsS --max-time 5 "$url"
    printf '\n'
  } >"$output_file" 2>&1 || true
  redact_file "$output_file"
}

create_diagnostics_archive() {
  local diagnostics_dir="$1"
  local archive_base="$2"
  local parent_dir
  local base_name
  parent_dir="$(dirname "$diagnostics_dir")"
  base_name="$(basename "$diagnostics_dir")"

  if command -v zip >/dev/null 2>&1; then
    (cd "$parent_dir" && zip -qr "${base_name}.zip" "$base_name")
    printf '%s.zip\n' "$diagnostics_dir"
    return
  fi

  tar -czf "${archive_base}.tar.gz" -C "$parent_dir" "$base_name"
  printf '%s.tar.gz\n' "$archive_base"
}

diagnostics_workbench() {
  check_docker
  local timestamp
  local diagnostics_dir
  local backend_port
  local archive_path
  timestamp="$(diagnostics_timestamp)"
  diagnostics_dir="diagnostics/workbench-diagnostics-${timestamp}"
  mkdir -p "$diagnostics_dir"

  {
    echo "created_at_utc=$timestamp"
    echo "compose_project_name=$COMPOSE_PROJECT_NAME"
    echo "frontend_port=${DOCKER_DEMO_FRONTEND_PORT:-$(running_frontend_port || true)}"
    echo "backend_port=${DOCKER_DEMO_BACKEND_PORT:-$(running_backend_port || true)}"
    echo "db_volume=$WORKBENCH_DB_VOLUME"
    echo "import_uploads_volume=$WORKBENCH_IMPORT_UPLOADS_VOLUME"
    echo "reports_volume=$WORKBENCH_REPORTS_VOLUME"
    echo "provider_snapshots_volume=$WORKBENCH_PROVIDER_SNAPSHOTS_VOLUME"
    echo "provider_cache_volume=$WORKBENCH_PROVIDER_CACHE_VOLUME"
  } >"${diagnostics_dir}/launcher-environment.txt"

  write_command_output "${diagnostics_dir}/docker-version.txt" docker version
  write_command_output "${diagnostics_dir}/docker-compose-version.txt" docker compose version
  write_command_output "${diagnostics_dir}/compose-ps.txt" docker compose "${COMPOSE_FILES[@]}" ps
  write_command_output "${diagnostics_dir}/compose-logs.txt" docker compose "${COMPOSE_FILES[@]}" logs --no-color --tail=250 backend frontend worker db

  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    write_command_output "${diagnostics_dir}/git-status.txt" git status --short --branch
    write_command_output "${diagnostics_dir}/git-commit.txt" git rev-parse HEAD
  else
    echo "Not a git checkout." >"${diagnostics_dir}/git-status.txt"
  fi

  backend_port="$(running_backend_port || true)"
  backend_port="${backend_port:-${DOCKER_DEMO_BACKEND_PORT:-}}"
  if [[ -n "$backend_port" ]]; then
    write_url_output "${diagnostics_dir}/backend-workbench-status.json" "http://127.0.0.1:${backend_port}/api/v1/workbench/status"
    write_url_output "${diagnostics_dir}/backend-provider-status.json" "http://127.0.0.1:${backend_port}/api/v1/providers/status"
    write_url_output "${diagnostics_dir}/backend-demo-status.json" "http://127.0.0.1:${backend_port}/api/v1/workbench/demo"
    write_url_output "${diagnostics_dir}/backend-health.txt" "http://127.0.0.1:${backend_port}/api/v1/utils/health-check/"
  else
    echo "Backend port is not available because the backend service is not running." >"${diagnostics_dir}/backend-status-skipped.txt"
  fi

  cat >"${diagnostics_dir}/README.txt" <<'EOF'
This diagnostics bundle intentionally excludes .env files, database dumps,
uploaded import files, generated reports, and provider cache contents.
Review files before sharing them outside your machine.
EOF

  archive_path="$(create_diagnostics_archive "$diagnostics_dir" "$diagnostics_dir")"
  echo "Created diagnostics bundle: $archive_path"
}

smoke_workbench() {
  check_docker
  require_command python3 "Install Python 3 to run the optional API smoke test."
  configure_ports_for_start
  DOCKER_QUICKSTART_API_BASE_URL="http://127.0.0.1:${DOCKER_DEMO_BACKEND_PORT}/api/v1" \
    python3 scripts/docker_quickstart_api_smoke.py
}

command="${1:-start}"
case "$command" in
  start)
    start_workbench
    ;;
  stop)
    stop_workbench
    ;;
  status)
    status_workbench
    ;;
  logs)
    logs_workbench
    ;;
  smoke)
    smoke_workbench
    ;;
  reset)
    reset_workbench
    ;;
  update)
    update_workbench
    ;;
  diagnostics)
    diagnostics_workbench
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    echo "Unknown command: $command" >&2
    usage >&2
    exit 1
    ;;
esac
