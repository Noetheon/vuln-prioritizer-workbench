#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

python_bin="${VPW_PYTHON:-python3}"
backend_port="${WORKBENCH_PLAYWRIGHT_BACKEND_PORT:-18000}"
db_path="${WORKBENCH_PLAYWRIGHT_DB:-$repo_root/build/frontend-playwright-workbench-$backend_port.db}"
report_dir="${WORKBENCH_PLAYWRIGHT_REPORT_DIR:-$repo_root/build/frontend-playwright-workbench-$backend_port-reports}"
mkdir -p "$(dirname "$db_path")"
mkdir -p "$report_dir"
rm -f -- "$db_path" "$db_path-wal" "$db_path-shm" "$db_path-journal"
rm -rf "$report_dir"
mkdir -p "$report_dir"

if [[ -n "${PYTHONPATH:-}" ]]; then
  export PYTHONPATH="$repo_root/backend:$PYTHONPATH"
else
  export PYTHONPATH="$repo_root/backend"
fi
export SQLALCHEMY_DATABASE_URI="sqlite:///$db_path"
export REPORT_DIR="$report_dir"
export PROVIDER_SNAPSHOT_DIR="$repo_root/data"
export DEMO_PROVIDER_SNAPSHOT_ENABLED=true
export DEMO_WORKSPACE_ENABLED=true
export RATE_LIMIT_ENABLED=false
export SECRET_KEY="${SECRET_KEY:-local-workbench-dev-secret}"
export WORKBENCH_FIXED_NOW="${WORKBENCH_FIXED_NOW:-2026-06-06T10:00:00+00:00}"
export TZ="${TZ:-UTC}"

"$python_bin" -m alembic -c backend/alembic.ini upgrade head

"$python_bin" -m app.workers.workflow_worker \
  --worker-id "playwright-worker-$backend_port" \
  --poll-interval 0.2 \
  --lease-seconds 30 \
  --retry-delay-seconds 0 &
worker_pid="$!"

cleanup() {
  kill "$worker_pid" 2>/dev/null || true
  wait "$worker_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

"$python_bin" -m uvicorn app.main:app --host 127.0.0.1 --port "$backend_port"
