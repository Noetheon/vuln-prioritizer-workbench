#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

db_path="${TEMPLATE_PLAYWRIGHT_DB:-$repo_root/build/frontend-playwright-template.db}"
report_dir="${TEMPLATE_PLAYWRIGHT_REPORT_DIR:-$repo_root/build/frontend-playwright-template-reports}"
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
export RATE_LIMIT_ENABLED=false

python3 -m app.core.migration_bootstrap
python3 -m alembic -c backend/alembic.ini upgrade head

exec python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000
