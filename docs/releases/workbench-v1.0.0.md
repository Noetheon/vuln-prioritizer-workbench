# Release Notes: Workbench v1.0.0

## Focus

Workbench `v1.0.0` is the first release-ready Workbench milestone on top of the stable CLI core. It keeps the product boundary narrow: known-CVE prioritization from existing inputs, not scanning, exploitation, or generated CVE-to-ATT&CK mapping.

These notes are Workbench milestone notes. The current package tree is versioned `1.1.0`, so a public package tag cut from `main` must use `v1.1.0` and the matching [v1.1.0 release notes](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/v1.1.0/docs/releases/v1.1.0.md).

## Features

- Local-first FastAPI Workbench with active `backend/app` runtime boundaries.
- Project, import, findings, vulnerability-intelligence, settings, governance, reports, and evidence views.
- Workbench import support for CVE lists, generic occurrence CSV, Trivy JSON, and Grype JSON.
- Provider snapshot persistence and `/api/v1/providers/status` freshness visibility.
- Optional ATT&CK context from local `ctid-json` files with review/rationale/confidence fields.
- Findings API pagination, filtering, sorting, and 10k pagination smoke coverage.
- Asset context, VEX, and waiver upload visibility with owner/service/governance rollups.
- JSON, Markdown, HTML, CSV, Navigator layer, and evidence bundle artifacts.
- Hardened local runtime defaults for host headers, upload paths, artifact downloads, security headers, secret redaction, and dependency audit checks.

## Non-Goals

- The Workbench is not a vulnerability scanner and does not probe, exploit, or validate live targets.
- Public-internet hosting, SaaS multi-tenancy, and organization-wide deployment hardening are outside this release scope.
- Heuristic, fuzzy, or AI-generated CVE-to-ATT&CK mapping is not a supported source of record.
- Evidence bundles are release and audit integrity artifacts, not encrypted vaults or detached-signature packages.

## Known Limitations

- The default deployment model is local-first and single-node.
- Repeatable release demos require the checked-in provider snapshot path; live provider feeds can drift after the release run.
- ATT&CK context is defensive and source-backed only; unmapped CVEs remain visibly unmapped.
- Imported vulnerability files can contain sensitive hostnames, package paths, image names, service names, owners, and environment labels, so demo and release evidence must avoid customer exports.

## Release Evidence

The v1.0 release gate recorded these historical acceptance criteria:

- #60-#64 tracker closure evidence
- `make workflow-check`
- `make docker-demo-smoke`
- `make dependency-audit`
- historical demo artifact sync and evidence-bundle verification from the
  then-active CLI release path
- README screenshots from the locked offline demo:
  `docs/examples/media/workbench-dashboard.png`,
  `docs/examples/media/workbench-findings.png`,
  `docs/examples/media/workbench-finding-detail-ttp.png`, and
  `docs/examples/media/workbench-reports-evidence.png`
- the completed checklist in [workbench-v1-release-checklist.md](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/v1.1.0/docs/workbench-v1-release-checklist.md)

Dependency audit disposition for the 2026-04-24 release pass: `make dependency-audit` completed successfully and `pip-audit` reported no known vulnerabilities for `requirements.txt`; there are no accepted dependency-audit exceptions for this release.

### Reproducible Demo Evidence Bundle

The reproducible demo bundle is generated from a repository checkout, the checked-in Trivy fixture, the checked-in asset context and VEX fixtures, the checked-in ATT&CK subset, and locked replay from `data/demo_provider_snapshot.json`. The `Makefile` pins `VULN_PRIORITIZER_FIXED_NOW=2026-04-21T12:00:00+00:00` for this path so release reviewers can compare artifacts without feed drift or local clock drift.

In the historical v1.0 release branch, reviewers generated and verified the
bundle with:

```bash
make demo-evidence-bundle-check
```

For an already generated bundle, the historical branch used the then-active CLI
verification path. That command surface has since been retired with the Typer
CLI. Current verification coverage lives in the Workbench report verification
service and the local quality gates documented in the active release checklist.

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
| `build/v1.0-demo-analysis.json` | `3d77cca073d02abcdd007fa9d3654ffcdb0574d3813f03fc6cd41f106ba2d3a3` | 95,610 bytes |
| `build/v1.0-demo-evidence-bundle.zip` | `a3a97bb176b80ea6c2136d6242975138e06bbcce08bc881d1c8dff044e32ef1f` | 45,862 bytes |
| `build/v1.0-demo-evidence-bundle-verification.json` | `bc17f21cc89a0dc2cb7eec6a2f4abf4bb5fb49310aee566b8ca4bd9f5005ed2d` | 3,003 bytes |
| `manifest.json` inside the ZIP | `77fb5060c4dca0a99f6f80c84ae5d74a8859e840751feeba51b3ecb7fb1f6467` | 3,302 bytes |

Manifest details for that run:

- `schema_version`: `1.1.0`
- `bundle_kind`: `evidence-bundle`
- `generated_at`: `2026-04-21T12:00:00+00:00`
- `source_analysis_sha256`: `3d77cca073d02abcdd007fa9d3654ffcdb0574d3813f03fc6cd41f106ba2d3a3`
- `provider_snapshot.path`: `demo_provider_snapshot.json`
- `provider_snapshot.sha256`: `d94b51defd676be1b852612d82d7f70aa213f1995af67a717c1ca6afb6c48f0c`
- `provider_snapshot.sources`: `nvd`, `epss`, `kev`
- verification summary: `ok=true`, `expected_files=6`, `verified_files=6`, `missing_files=0`, `modified_files=0`, `unexpected_files=0`, `manifest_errors=0`

Manifest file entries:

| Bundle member | Kind | SHA-256 | Size |
| --- | --- | --- | ---: |
| `analysis.json` | `analysis-json` | `5a05ced10c550b27261ef433563708de2d831e134ad907d992004cbb3839fe39` | 95,587 bytes |
| `report.html` | `html-report` | `3e3995ab3d49982dc8291cf43570a3861ddca1e6c6755da9c7760f6af9d91ddf` | 101,449 bytes |
| `summary.md` | `markdown-summary` | `206e3e9d10e426f7f6fd413ce6c988a3b0b8de2a060d50f0e75f78b09977202b` | 3,950 bytes |
| `attack-navigator-layer.json` | `attack-navigator-layer` | `18d94bbe54e47b27c10db18eeaade92b4ceddd3ab08b2370625f08c866f9d331` | 1,825 bytes |
| `provider/provider-snapshot.json` | `provider-snapshot` | `d94b51defd676be1b852612d82d7f70aa213f1995af67a717c1ca6afb6c48f0c` | 60,530 bytes |
| `input/trivy_report.json` | `source-input` | `24d65249ea6f77b56c7870df3dd98bc8120294b886e226117c40b22e4825a81d` | 2,188 bytes |

Record the release commit with `git rev-parse HEAD`, the date of the run, and the exact command output. Do not include `.env` files, API keys, cookies, shell history, machine-specific home paths, or customer scanner exports in the public release evidence.

## Guardrails

- Base priority remains explainable from CVSS, EPSS, and KEV.
- ATT&CK is contextual only and does not change base priority.
- `ctid-json` remains the canonical Workbench ATT&CK path.
- Heuristic, fuzzy, or LLM-generated CVE-to-ATT&CK mappings are not supported as source of record.
- Evidence bundles are integrity artifacts, not encrypted archives.
- The Workbench remains local-first and single-node; public-internet or multi-tenant deployment is out of this release scope.

## Post-Milestone Status

- The pinned ATT&CK STIX import, ATT&CK version/hash tracking, CTID provider
  provenance, and detection coverage work landed after this Workbench v1.0
  readiness milestone and remain part of the current Workbench evidence model.
- API-token gating, optional PostgreSQL profile, scheduled provider update jobs,
  SARIF/Action workflow expansion, GitHub issue export, config-as-code, and
  CI/CD docs belonged to post-v1.0 package-line work in the historical
  `v1.1.0` tree. Current `main` has since narrowed the active product to the
  local single-user Workbench and does not expose API-token gating, RBAC,
  login/session flows, or the old CLI/Action product surface.
- The `v1.1.0` package tag and GitHub Release now carry the completed Workbench scope from `main`; future Workbench work should be tracked as new issues rather than as unfinished v1.0 follow-up.
