#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

backend_port="${WORKBENCH_PLAYWRIGHT_BACKEND_PORT:-18000}"
db_path="${WORKBENCH_PLAYWRIGHT_DB:-$repo_root/build/frontend-playwright-workbench-$backend_port.db}"
report_dir="${WORKBENCH_PLAYWRIGHT_REPORT_DIR:-$repo_root/build/frontend-playwright-workbench-$backend_port-reports}"
mkdir -p "$(dirname "$db_path")"
mkdir -p "$report_dir"
rm -f "$db_path"
rm -rf "$report_dir"
mkdir -p "$report_dir"

if [[ -n "${PYTHONPATH:-}" ]]; then
  export PYTHONPATH="$repo_root/backend:$repo_root/backend/src:$PYTHONPATH"
else
  export PYTHONPATH="$repo_root/backend:$repo_root/backend/src"
fi
export SQLALCHEMY_DATABASE_URI="sqlite:///$db_path"
export REPORT_DIR="$report_dir"
export PROVIDER_SNAPSHOT_DIR="$repo_root/data"
export DEMO_PROVIDER_SNAPSHOT_ENABLED=true
export DEMO_WORKSPACE_ENABLED=true
export RATE_LIMIT_ENABLED=false
export SECRET_KEY="${SECRET_KEY:-local-workbench-dev-secret}"

python3 -m alembic -c backend/alembic.ini upgrade head

exec python3 -m uvicorn app.main:app --host 127.0.0.1 --port "$backend_port"
