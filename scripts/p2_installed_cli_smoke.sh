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

INPUT_FILE="$ROOT_DIR/data/input_fixtures/github_alerts_export.json"
ASSET_CONTEXT_FILE="$TMP_DIR/asset-context.csv"
VEX_FILE="$TMP_DIR/p2-vex.json"
SNAPSHOT_FILE="$TMP_DIR/provider-snapshot.json"
ANALYZE_OUTPUT="$TMP_DIR/p2-analysis.json"
COMPARE_OUTPUT="$TMP_DIR/p2-compare.json"
EXPLAIN_OUTPUT="$TMP_DIR/p2-explain.json"
SNAPSHOT_OUTPUT="$TMP_DIR/p2-snapshot.json"
ROLLUP_OUTPUT="$TMP_DIR/p2-rollup.json"

cat > "$ASSET_CONTEXT_FILE" <<'EOF'
rule_id,target_kind,target_ref,asset_id,match_mode,precedence,criticality,owner,business_service
glob-rule,repository,*requirements.txt,asset-glob,glob,10,medium,team-platform,identity
exact-rule,repository,backend/requirements.txt,asset-exact,exact,10,critical,team-platform,identity
EOF

cat > "$VEX_FILE" <<'EOF'
{
  "statements": [
    {
      "vulnerability": { "name": "CVE-2023-34362" },
      "status": "under_investigation",
      "products": [{ "subcomponents": [{ "kind": "repository", "name": "backend/requirements.txt" }] }]
    },
    {
      "vulnerability": { "name": "CVE-2023-34362" },
      "status": "fixed",
      "products": [{ "subcomponents": [{ "kind": "repository", "name": "backend/requirements.txt" }] }]
    }
  ]
}
EOF

"$PYTHON_BIN" - "$SNAPSHOT_FILE" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

snapshot_path = Path(sys.argv[1])
payload = {
    "metadata": {
        "schema_version": "1.2.0",
        "artifact_kind": "provider-snapshot",
        "generated_at": "2026-04-22T12:00:00Z",
        "input_path": "github_alerts_export.json",
        "input_paths": ["github_alerts_export.json"],
        "input_format": "github-alerts-json",
        "selected_sources": ["nvd", "epss", "kev"],
        "requested_cves": 1,
        "output_path": str(snapshot_path),
        "cache_enabled": False,
        "cache_dir": None,
        "offline_kev_file": None,
        "nvd_api_key_env": None,
    },
    "items": [
        {
            "cve_id": "CVE-2023-34362",
            "nvd": {
                "cve_id": "CVE-2023-34362",
                "description": "MOVEit Transfer SQL injection",
                "cvss_base_score": 9.8,
                "cvss_severity": "CRITICAL",
                "cvss_version": "3.1",
                "published": None,
                "last_modified": None,
                "cwes": [],
                "references": [],
            },
            "epss": {
                "cve_id": "CVE-2023-34362",
                "epss": 0.943,
                "percentile": 0.999,
                "date": "2026-04-20",
            },
            "kev": {
                "cve_id": "CVE-2023-34362",
                "in_kev": True,
                "vendor_project": "Progress",
                "product": "MOVEit Transfer",
                "date_added": None,
                "required_action": None,
                "due_date": None,
            },
        }
    ],
    "warnings": [],
}
snapshot_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

"${CLI[@]}" analyze \
  --input "$INPUT_FILE" \
  --input-format github-alerts-json \
  --asset-context "$ASSET_CONTEXT_FILE" \
  --vex-file "$VEX_FILE" \
  --provider-snapshot-file "$SNAPSHOT_FILE" \
  --locked-provider-data \
  --format json \
  --output "$ANALYZE_OUTPUT"

"$PYTHON_BIN" - "$ANALYZE_OUTPUT" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
metadata = payload["metadata"]
finding = payload["findings"][0]
occurrence = next(
    item for item in finding["provenance"]["occurrences"] if item["target_ref"] == "backend/requirements.txt"
)

assert metadata["locked_provider_data"] is True
assert metadata["asset_match_conflict_count"] == 1
assert metadata["vex_conflict_count"] == 1
assert finding["remediation"]["strategy"] == "upgrade"
assert finding["remediation"]["components"][0]["fixed_versions"] == ["2023.0.2"]
assert occurrence["asset_id"] == "asset-exact"
assert occurrence["asset_match_rule_id"] == "exact-rule"
assert occurrence["vex_status"] == "under_investigation"
assert occurrence["vex_match_type"] == "target"
PY

"${CLI[@]}" compare \
  --input "$INPUT_FILE" \
  --input-format github-alerts-json \
  --asset-context "$ASSET_CONTEXT_FILE" \
  --vex-file "$VEX_FILE" \
  --provider-snapshot-file "$SNAPSHOT_FILE" \
  --locked-provider-data \
  --format json \
  --output "$COMPARE_OUTPUT"

"$PYTHON_BIN" - "$COMPARE_OUTPUT" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
comparison = payload["comparisons"][0]
assert comparison["under_investigation"] is True
assert payload["metadata"]["vex_conflict_count"] == 1
PY

"${CLI[@]}" explain \
  --cve CVE-2023-34362 \
  --asset-context "$ASSET_CONTEXT_FILE" \
  --vex-file "$VEX_FILE" \
  --target-kind repository \
  --target-ref backend/requirements.txt \
  --provider-snapshot-file "$SNAPSHOT_FILE" \
  --locked-provider-data \
  --format json \
  --output "$EXPLAIN_OUTPUT"

"$PYTHON_BIN" - "$EXPLAIN_OUTPUT" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
occurrence = payload["finding"]["provenance"]["occurrences"][0]
assert any("Asset context resolved" in warning for warning in payload["metadata"]["warnings"])
assert any("VEX resolved" in warning for warning in payload["metadata"]["warnings"])
assert occurrence["asset_match_rule_id"] == "exact-rule"
assert occurrence["vex_status"] == "under_investigation"
PY

"${CLI[@]}" snapshot create \
  --input "$INPUT_FILE" \
  --input-format github-alerts-json \
  --asset-context "$ASSET_CONTEXT_FILE" \
  --vex-file "$VEX_FILE" \
  --provider-snapshot-file "$SNAPSHOT_FILE" \
  --locked-provider-data \
  --format json \
  --output "$SNAPSHOT_OUTPUT"

"$PYTHON_BIN" - "$SNAPSHOT_OUTPUT" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert payload["metadata"]["snapshot_kind"] == "snapshot"
assert payload["findings"][0]["remediation"]["strategy"] == "upgrade"
PY

"${CLI[@]}" rollup \
  --input "$SNAPSHOT_OUTPUT" \
  --by asset \
  --format json \
  --output "$ROLLUP_OUTPUT"

"$PYTHON_BIN" - "$ROLLUP_OUTPUT" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
bucket = payload["buckets"][0]
assert payload["metadata"]["dimension"] == "asset"
assert bucket["bucket"] == "asset-exact"
assert bucket["top_candidates"][0]["remediation"]["strategy"] == "upgrade"
assert bucket["recommended_actions"]
PY
