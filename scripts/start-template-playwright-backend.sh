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

python3 - <<'PY'
from sqlmodel import Session

from app.core.db import engine, init_db
from app.models import import_table_models

import_table_models()
with Session(engine) as session:
    init_db(session)
PY

exec python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000
