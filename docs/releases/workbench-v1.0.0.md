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
- screenshots listed in [workbench-offline-demo.md](../workbench-offline-demo.md)
- the completed checklist in [workbench-v1-release-checklist.md](../workbench-v1-release-checklist.md)

Dependency audit disposition for the 2026-04-24 release pass: `make dependency-audit` completed successfully and `pip-audit` reported no known vulnerabilities for `requirements.txt`; there are no accepted dependency-audit exceptions for this release.

Generated release-evidence artifact paths:

- `build/v1.0-demo-analysis.json`
- `build/v1.0-demo-evidence-bundle.zip`
- `build/v1.0-demo-evidence-bundle-verification.json`

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
