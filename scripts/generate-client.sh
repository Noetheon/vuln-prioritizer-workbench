#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

if [[ -n "${PYTHONPATH:-}" ]]; then
  export PYTHONPATH="$PYTHONPATH:$repo_root/backend:$repo_root/backend/src"
else
  export PYTHONPATH="$repo_root/backend:$repo_root/backend/src"
fi

python3 - <<'PY'
import json
from pathlib import Path

from app.main import app

Path("frontend/openapi.json").write_text(
    json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

npm --prefix frontend run generate-client

python3 - <<'PY'
from pathlib import Path

for path in sorted(Path("frontend/src/client").rglob("*.ts")):
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(line.rstrip() for line in lines) + "\n", encoding="utf-8")
PY
