# Release Notes: Workbench v1.0.0

## Focus

Workbench `v1.0.0` is the first release-ready Workbench milestone on top of the stable CLI core. It keeps the product boundary narrow: known-CVE prioritization from existing inputs, not scanning, exploitation, or generated CVE-to-ATT&CK mapping.

## Included Scope

- Local-first FastAPI and Jinja2 Workbench with SQLite default storage.
- Project, import, findings, vulnerability-intelligence, settings, governance, reports, and evidence views.
- Workbench import support for CVE lists, generic occurrence CSV, Trivy JSON, and Grype JSON.
- Provider snapshot persistence and `/api/providers/status` freshness visibility.
- Optional ATT&CK context from local `ctid-json` files with review/rationale/confidence fields.
- Findings API pagination, filtering, sorting, and 10k pagination smoke coverage.
- Asset context, VEX, and waiver upload visibility with owner/service/governance rollups.
- JSON, Markdown, HTML, CSV, Navigator layer, and evidence bundle artifacts.
- Hardened local runtime defaults for host headers, upload paths, artifact downloads, security headers, secret redaction, and dependency audit checks.

## Release Evidence

The v1.0 release gate should attach or record:

- #60-#64 tracker closure evidence
- `make workflow-check`
- `make docker-demo-smoke`
- `make dependency-audit`
- `make demo-sync-check-temp`
- a verified demo evidence bundle from `make demo-evidence-bundle-check`
- README screenshots from the locked offline demo:
  `docs/examples/media/workbench-dashboard.png`,
  `docs/examples/media/workbench-findings.png`,
  `docs/examples/media/workbench-finding-detail-ttp.png`, and
  `docs/examples/media/workbench-reports-evidence.png`
- the completed checklist in [workbench-v1-release-checklist.md](../workbench-v1-release-checklist.md)

Dependency audit disposition for the 2026-04-24 release pass: `make dependency-audit` completed successfully and `pip-audit` reported no known vulnerabilities for `requirements.txt`; there are no accepted dependency-audit exceptions for this release.

### Reproducible Demo Evidence Bundle

The reproducible demo bundle is generated from a repository checkout, the checked-in Trivy fixture, the checked-in asset context and VEX fixtures, the checked-in ATT&CK subset, and locked replay from `data/demo_provider_snapshot.json`. The `Makefile` pins `VULN_PRIORITIZER_FIXED_NOW=2026-04-21T12:00:00+00:00` for this path so release reviewers can compare artifacts without feed drift or local clock drift.

Generate and verify the bundle with:

```bash
make demo-evidence-bundle-check
```

For an already generated bundle, the verification command is:

```bash
PYTHONPATH=src VULN_PRIORITIZER_FIXED_NOW=2026-04-21T12:00:00+00:00 \
  python3 -m vuln_prioritizer.cli report verify-evidence-bundle \
  --input build/v1.0-demo-evidence-bundle.zip \
  --output build/v1.0-demo-evidence-bundle-verification.json \
  --format json
```

Expected release-evidence artifact paths:

- `build/v1.0-demo-analysis.json`
- `build/v1.0-demo-evidence-bundle.zip`
- `build/v1.0-demo-evidence-bundle-verification.json`

The verification report must record `summary.ok` as `true`, with zero missing, modified, unexpected, or manifest-error entries. The evidence ZIP contains `manifest.json`, whose file entries, artifact hashes, source analysis hash, source input hashes, and provider snapshot metadata are the bundle's internal integrity record.

Release notes or external evidence folders should record the SHA-256 values of the generated files without copying local absolute paths:

```bash
shasum -a 256 \
  build/v1.0-demo-analysis.json \
  build/v1.0-demo-evidence-bundle.zip \
  build/v1.0-demo-evidence-bundle-verification.json
```

Record the release-candidate commit with `git rev-parse HEAD`, the date of the run, and the exact command output. Do not include `.env` files, API keys, cookies, shell history, machine-specific home paths, or customer scanner exports in the public release evidence.

## Guardrails

- Base priority remains explainable from CVSS, EPSS, and KEV.
- ATT&CK is contextual only and does not change base priority.
- `ctid-json` remains the canonical Workbench ATT&CK path.
- Heuristic, fuzzy, or LLM-generated CVE-to-ATT&CK mappings are not supported as source of record.
- Evidence bundles are integrity artifacts, not encrypted archives.
- The Workbench remains local-first and single-node; public-internet or multi-tenant deployment is out of this release scope.

## Known Follow-up

- v1.1 starts the pinned ATT&CK STIX import, ATT&CK version/hash tracking, CTID provider provenance, and detection coverage work.
- v1.2 starts authentication, optional PostgreSQL, scheduled provider update jobs, SARIF/Action workflow expansion, GitHub issue export, config-as-code, and CI/CD docs.
