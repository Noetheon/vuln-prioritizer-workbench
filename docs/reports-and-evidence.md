# Reports and Evidence

The Evidence Center turns selected project runs into reviewable artifacts. The
goal is audit-ready defensive evidence, not exploit proof.

## Evidence Center

The current React Evidence Center lives in
`frontend/src/components/reports/EvidenceCenter.tsx`. It shows:

- selected project and run readiness
- provider and report-input context
- report format cards
- generated report list
- checksum and manifest metadata
- evidence bundle status and verification actions

Report generation, download, and verification are still handled through the
Workbench backend API. The frontend does not invent report content or bypass
checksum validation.

## Report Formats

The current report surface supports:

| Format | Purpose |
| --- | --- |
| HTML | Executive browser report with priority summary and evidence links. |
| Markdown | Technical handoff for analysts, PR notes, and audit review. |
| JSON | Machine-readable analysis and report data. |
| CSV | Finding table export for spreadsheets and ticket routing. |
| SARIF | Code-scanning and CI evidence workflows. |
| ATT&CK Navigator | Defensive layer for mapped techniques when ATT&CK context exists. |
| Evidence ZIP Bundle | Bundle containing reports, source artifacts, manifest, and SHA256 checksums. |

Available formats depend on the selected run and report action state. Demo data
is labeled as demo-only and should not be presented as production evidence.

## Evidence ZIP Bundle

The Evidence ZIP Bundle is the strongest audit artifact. It is expected to
contain generated reports plus a manifest that records file names, sizes, and
SHA256 checksums.

Verification checks that bundle contents still match the manifest. Tampered or
missing artifacts should fail verification instead of being treated as usable
evidence.

## Canonical Contract Artifacts

`docs/evidence/` intentionally remains small. It contains only committed
contract artifacts used by backend report/evidence tests:

- `docs/evidence/vpw-050-analysis-result.v1.json`
- `docs/evidence/vpw-050-findings.csv`
- `docs/evidence/vpw-051-analysis.json`
- `docs/evidence/vpw-051-manifest.json`
- `docs/evidence/vpw-052-positive-verification.json`
- `docs/evidence/vpw-052-tampered-verification.json`
- `docs/evidence/vpw-054-report-snapshots.md`
- `docs/evidence/vpw-060-attack-navigator-layer.json`

Do not add screenshots, broad historical evidence, or ad hoc demo artifacts
under `docs/evidence/`. The docs hygiene test enforces this boundary.

## Evidence Ownership Matrix

| Location | Owner | Use | Boundary |
| --- | --- | --- | --- |
| `docs/evidence/` | Backend/API contract owners | Small, reviewed contract fixtures referenced by schemas or regression tests. | No screenshots, ad hoc logs, demo bundles, or historical issue proof. |
| `archive/vpw-evidence/` | Release and roadmap maintainers | Public-safe historical VPW evidence, scorecards, screenshots, demo summaries, and issue closeout artifacts. | Keep entrypoints in `archive/vpw-evidence/MANIFEST.md`; add redacted summaries instead of raw local logs. |
| CI artifacts | Release owner for the exact run | Ephemeral command output, package files, Docker logs, Playwright reports, and release-readiness bundles for a commit, tag, or PR. | Link from the PR/issue/release evidence comment; do not copy raw artifacts into `docs/evidence/`. |
| Historical screenshots | Demo or submission owner | Locked UI proof referenced by submission and demo documentation. | Store under `archive/vpw-evidence/` or a named subdirectory; do not duplicate screenshots across docs pages. |

New VPW-AUD evidence should be a small tracked Markdown summary under
`archive/vpw-evidence/` when it must survive the PR, or an external CI artifact
link when the raw output belongs to the exact workflow run. Evidence comments
must identify which path was used and why.

## Historical Evidence Archive

Historical VPW evidence now lives under `archive/vpw-evidence/`. Important
entrypoints:

- `archive/vpw-evidence/README.md`
- `archive/vpw-evidence/MANIFEST.md`
- `archive/vpw-evidence/final-demo-flow/demo-flow-summary.md`
- `archive/vpw-evidence/final-demo-flow/attack-demo-mapping-summary.md`
- `archive/vpw-evidence/presentation-pack/README.md`
- `archive/vpw-evidence/presentation-pack/evidence-index.md`

The archive preserves screenshots, issue closeout notes, validation logs,
presentation-pack references, and old milestone evidence without making the
public `docs/evidence/` tree sprawl again.

## Safety Boundary

Reports and evidence may describe CVSS, EPSS, KEV, provider freshness, asset
context, waivers, ATT&CK mappings, and detection coverage. They must not claim
that a local environment was exploited unless a cited source explicitly supports
that statement. ATT&CK context is defensive triage context and does not prove
exploitation.
