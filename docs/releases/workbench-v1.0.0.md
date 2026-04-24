# Release Notes: Workbench v1.0.0

## Focus

Workbench `v1.0.0` is the first release-ready Workbench milestone on top of the stable CLI core. It keeps the product boundary narrow: known-CVE prioritization from existing inputs, not scanning, exploitation, or generated CVE-to-ATT&CK mapping.

These notes are Workbench milestone notes. The current package tree is versioned `1.1.0`, so a public package tag cut from `main` must use `v1.1.0` and the matching [v1.1.0 release notes](v1.1.0.md).

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

Reference release evidence run from the locked demo path:

| Artifact | SHA-256 | Size |
| --- | --- | ---: |
| `build/v1.0-demo-analysis.json` | `89c65a424db58de2313d44d201c63c806155a3543d5ee1af8dc12512e5e3d77b` | 49,024 bytes |
| `build/v1.0-demo-evidence-bundle.zip` | `246a80012271deae22be15dfbb7e24408c2431324b0a244cbe0e0ec58c8dbad2` | 28,473 bytes |
| `build/v1.0-demo-evidence-bundle-verification.json` | `c1da50f6c006859b2737b99d1d6917c583fda05101ef663012ae432a7bca9634` | 2,566 bytes |
| `manifest.json` inside the ZIP | `1c828e916bd7b0e1427921acde2c77efff8c30b8790992eed010ea241fafffbb` | 2,497 bytes |

Manifest details for that run:

- `schema_version`: `1.1.0`
- `bundle_kind`: `evidence-bundle`
- `generated_at`: `2026-04-21T12:00:00+00:00`
- `source_analysis_sha256`: `89c65a424db58de2313d44d201c63c806155a3543d5ee1af8dc12512e5e3d77b`
- `provider_snapshot.path`: `data/demo_provider_snapshot.json`
- `provider_snapshot.sha256`: `a110e4c372a5ec750e0b766e23f19884596f6ac82185b8fd0eefe8384be71c5b`
- `provider_snapshot.sources`: `nvd`, `epss`, `kev`
- verification summary: `ok=true`, `expected_files=5`, `verified_files=5`, `missing_files=0`, `modified_files=0`, `unexpected_files=0`, `manifest_errors=0`

Manifest file entries:

| Bundle member | Kind | SHA-256 | Size |
| --- | --- | --- | ---: |
| `analysis.json` | `analysis-json` | `89c65a424db58de2313d44d201c63c806155a3543d5ee1af8dc12512e5e3d77b` | 49,024 bytes |
| `report.html` | `html-report` | `9b958bf1103add7731b8068fa2fef61353f6a01a8cb47ea979b77dd6e0988f97` | 109,325 bytes |
| `summary.md` | `markdown-summary` | `916377f25d8a84db8d338201c9e413d5df7a9518a0f2d06ece66e405fade10a3` | 3,038 bytes |
| `attack-navigator-layer.json` | `attack-navigator-layer` | `18d94bbe54e47b27c10db18eeaade92b4ceddd3ab08b2370625f08c866f9d331` | 1,825 bytes |
| `input/trivy_report.json` | `source-input` | `43b29a02a88bc6d9c8c2e8d599a5218fcc253f025f42acbcc780e377bad26e82` | 2,200 bytes |

Record the release commit with `git rev-parse HEAD`, the date of the run, and the exact command output. Do not include `.env` files, API keys, cookies, shell history, machine-specific home paths, or customer scanner exports in the public release evidence.

## Guardrails

- Base priority remains explainable from CVSS, EPSS, and KEV.
- ATT&CK is contextual only and does not change base priority.
- `ctid-json` remains the canonical Workbench ATT&CK path.
- Heuristic, fuzzy, or LLM-generated CVE-to-ATT&CK mappings are not supported as source of record.
- Evidence bundles are integrity artifacts, not encrypted archives.
- The Workbench remains local-first and single-node; public-internet or multi-tenant deployment is out of this release scope.

## Post-Milestone Status

- The pinned ATT&CK STIX import, ATT&CK version/hash tracking, CTID provider provenance, and detection coverage work were completed on `main` after this Workbench v1.0 readiness milestone.
- Local API-token gating, optional PostgreSQL profile, scheduled provider update jobs, SARIF/Action workflow expansion, GitHub issue export, config-as-code, and CI/CD docs were completed on `main` after this Workbench v1.0 readiness milestone.
- The `v1.1.0` package tag and GitHub Release now carry the completed Workbench scope from `main`; future Workbench work should be tracked as new issues rather than as unfinished v1.0 follow-up.
