#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="${VULN_PRIORITIZER_SMOKE_OUTPUT_DIR:-}"
if [[ -n "$TMP_DIR" ]]; then
  mkdir -p "$TMP_DIR"
  CLEANUP_TMP_DIR=0
else
  TMP_DIR="$(mktemp -d)"
  CLEANUP_TMP_DIR=1
fi
trap '[[ "$CLEANUP_TMP_DIR" == "1" ]] && rm -rf "$TMP_DIR"' EXIT
PYTHON_BIN="${PYTHON_BIN:-python3}"

if [[ "${VULN_PRIORITIZER_USE_MODULE:-0}" == "1" ]]; then
  CLI=("$PYTHON_BIN" -m vuln_prioritizer.cli)
elif [[ -n "${VULN_PRIORITIZER_PIPX_SPEC:-}" ]]; then
  CLI=("$PYTHON_BIN" -m pipx run --spec "$VULN_PRIORITIZER_PIPX_SPEC" vuln-prioritizer)
else
  CLI=(vuln-prioritizer)
fi

MULTI_INPUT_OUTPUT="$TMP_DIR/multi-input-analysis.json"
SNAPSHOT_INPUT="$TMP_DIR/provider-snapshot-cves.txt"
SNAPSHOT_OUTPUT="$TMP_DIR/provider-snapshot.json"
LOCKED_OUTPUT="$TMP_DIR/locked-analysis.json"

cat > "$SNAPSHOT_INPUT" <<'EOF'
CVE-2021-44228
CVE-2023-44487
EOF

"${CLI[@]}" analyze \
  --input "$ROOT_DIR/data/sample_cves.txt" \
  --input "$ROOT_DIR/data/input_fixtures/github_alerts_export.json" \
  --input-format cve-list \
  --input-format github-alerts-json \
  --format json \
  --output "$MULTI_INPUT_OUTPUT"

"$PYTHON_BIN" - "$MULTI_INPUT_OUTPUT" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
metadata = payload["metadata"]
assert metadata["merged_input_count"] == 2
assert metadata["input_format"] == "mixed"
assert len(metadata["input_paths"]) == 2
PY

"${CLI[@]}" data export-provider-snapshot \
  --input "$SNAPSHOT_INPUT" \
  --output "$SNAPSHOT_OUTPUT" \
  --source nvd \
  --source epss \
  --source kev

"$PYTHON_BIN" - "$SNAPSHOT_OUTPUT" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert payload["metadata"]["artifact_kind"] == "provider-snapshot"
assert payload["metadata"]["requested_cves"] == 2
assert payload["metadata"]["selected_sources"] == ["nvd", "epss", "kev"]
assert len(payload["items"]) == 2
PY

"${CLI[@]}" analyze \
  --input "$SNAPSHOT_INPUT" \
  --format json \
  --output "$LOCKED_OUTPUT" \
  --provider-snapshot-file "$SNAPSHOT_OUTPUT" \
  --locked-provider-data

"$PYTHON_BIN" - "$LOCKED_OUTPUT" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
metadata = payload["metadata"]
assert metadata["locked_provider_data"] is True
assert metadata["provider_snapshot_sources"] == ["nvd", "epss", "kev"]
assert len(payload["findings"]) == 2
PY
