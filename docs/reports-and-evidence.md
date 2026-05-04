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
