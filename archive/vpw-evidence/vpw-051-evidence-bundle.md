# VPW-051 Evidence Bundle ZIP Evidence

VPW-051 adds a verifiable ZIP export for completed template-stack analysis
runs. It reuses the existing authenticated report artifact endpoint, report
root validation, SHA-256 download validation, and project visibility checks.

## Implemented Scope

- `ReportCreate.format` now accepts `zip`.
- `POST /api/v1/runs/{run_id}/reports` creates `evidence-bundle` as
  `evidence-bundle.zip`.
- The ZIP has fixed member names:
  - `manifest.json`
  - `analysis.json`
  - `technical.md`
  - `executive.html`
  - `provider-snapshot.json`
- `manifest.json` records `files[]` and `artifact_hashes` SHA-256 values for
  every bundled file except `manifest.json`.
- Source input bytes are not copied into the bundle. When upload metadata is
  present, the manifest records `source_input_hashes`.
- Sensitive keys, token-like values, and local path fields are replaced with
  `[REDACTED]` before bundle members are rendered.

## Example Artifacts

```text
docs/evidence/vpw-051-evidence-bundle.zip
docs/evidence/vpw-051-analysis.json
docs/evidence/vpw-051-manifest.json
```

## Manifest Excerpt

```json
{
  "bundle_kind": "evidence-bundle",
  "included_input_copy": false,
  "source_analysis_path": "analysis.json",
  "files": [
    {
      "kind": "analysis-json",
      "path": "analysis.json"
    }
  ]
}
```

The full manifest validates against
`docs/schemas/evidence-bundle-manifest.schema.json`.

## Security Review

- ZIP member names are static and do not use user-provided paths.
- Download validation remains rooted under `REPORT_DIR`.
- Download responses retain `Cache-Control: no-store` and
  `X-Content-Type-Options: nosniff`.
- Input files are represented by hash metadata only; raw upload copies are not
  included.
- Redaction covers secret-like keys, token-like values, absolute local paths,
  and `*_path` / `*_dir` fields across JSON, Markdown, and HTML bundle members.
- Integrity is checksum-based tamper detection, not provenance signing.

## Local Verification

```bash
python3 -m pytest -q backend/tests/api/test_template_reports_api.py --no-cov
python3 -m pytest -q backend/tests/test_output_schemas.py backend/tests/test_evidence_bundle_verification.py --no-cov
python3 -m ruff check backend/app backend/src/vuln_prioritizer/models_artifacts.py backend/tests/api/test_template_reports_api.py backend/tests/test_evidence_bundle_verification.py
python3 -m ruff format --check backend/app backend/src/vuln_prioritizer/models_artifacts.py backend/tests/api/test_template_reports_api.py backend/tests/test_evidence_bundle_verification.py
python3 -m mkdocs build --clean
make frontend-check
make check
npm --prefix frontend run test
PYTHONPATH=backend/src python3 - <<'PY'
from pathlib import Path
from vuln_prioritizer.reporting_evidence import verify_evidence_bundle
_, summary, _ = verify_evidence_bundle(Path("docs/evidence/vpw-051-evidence-bundle.zip"))
assert summary.ok
assert summary.verified_files == 4
PY
git diff --check
```

Results captured during implementation:

- Template report API tests: 16 passed.
- Output schema and evidence-bundle verification tests: 32 passed.
- Ruff check and format-check: passed.
- MkDocs build: passed.
- Frontend check: Biome lint, Vite build, and generated client passed.
- Full `make check`: 750 passed, 5 skipped, coverage 90.60%.
- Frontend Playwright smoke: 1 passed.
- Evidence bundle verification summary: `ok=true`, `verified_files=4`,
  `missing_files=0`, `modified_files=0`, `unexpected_files=0`,
  `manifest_errors=0`.
- Whitespace check: passed.

## Residual Risk

The bundle records per-file SHA-256 checksums and can detect local tampering,
but it does not provide signing, timestamp authority, or external provenance
attestation.
