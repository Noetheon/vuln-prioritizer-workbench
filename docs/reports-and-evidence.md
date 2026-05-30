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

Report generation is queued through Workflow v2 and completed by the durable
worker. Report content is projected from the Decision/Evidence Kernel v2
contracts, not from free-form workflow JSON. Download and verification stay
behind the Workbench backend API. The frontend does not invent report content,
treat a queued report as finished, or bypass checksum validation.

All report formats are rendered from the same persisted evidence snapshot used
by run and finding APIs: run-wide `AnalysisEvidenceV2` plus per-finding
`FindingDecisionEvidenceV2`. Individual renderers must not reconstruct counts,
provider facts, VEX state, governance signals, or occurrence semantics from
successful workflow result JSON.

## Report Formats

The current report surface supports:

| Format | Purpose |
| --- | --- |
| HTML | Executive browser report with priority summary and evidence links. |
| Markdown | Technical handoff for analysts, PR notes, and audit review. |
| JSON | Machine-readable `analysis-result.v2.json` analysis and report data. |
| CSV | Finding table export for spreadsheets and ticket routing. |
| SARIF | Code-scanning and CI evidence workflows. |
| ATT&CK Navigator | Defensive layer for mapped techniques when ATT&CK context exists. |
| Evidence ZIP Bundle | Bundle containing reports, source artifacts, manifest, and SHA256 checksums. |

Available formats depend on the selected run and report action state. The local
demo workspace is seeded through the backend and should be treated as sample
evidence, not production evidence.

## Evidence ZIP Bundle

The Evidence ZIP Bundle is the most complete local audit artifact. It contains
generated reports plus a manifest that records file names, sizes, and SHA256
checksums. Current bundle contents include `manifest.json`, `analysis.json`,
`technical.md`, `executive.html`, `provider-snapshot.json`, `findings.csv`,
`results.sarif`, optional `attack-navigator-layer.json`, and optional
governance artifacts under `governance/`.

Verification checks that bundle contents still match the manifest. Tampered or
missing artifacts should fail verification instead of being treated as usable
evidence. Verification is an integrity check for the generated ZIP; it is not a
cryptographic signature, custody attestation, or proof that provider data was
fresh at review time.

## Canonical Contract Artifacts

`docs/evidence/` intentionally remains small. It contains only committed
contract artifacts used by backend report/evidence tests:

- `docs/evidence/vpw-050-analysis-result.v2.json`
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
| `archive/vpw-evidence/` | Release and roadmap maintainers | Minimal public-safe historical VPW entrypoints, selected Markdown notes, and the retained evidence bundle. | Keep entrypoints in `archive/vpw-evidence/MANIFEST.md`; add tracked artifacts only when current docs or tests need them. |
| CI artifacts | Release owner for the exact run | Ephemeral command output, package files, Docker logs, Playwright reports, and release-readiness bundles for a commit, tag, or PR. | Link from the PR/issue/release evidence comment; do not copy raw artifacts into `docs/evidence/`. |
| Historical screenshots | Demo or submission owner | Optional UI proof for a specific run. | Prefer CI artifacts or fresh Playwright output; do not commit screenshot sets to `archive/**` unless a maintainer explicitly accepts the repository-size cost. |

New VPW-AUD evidence should normally live in the PR/issue closeout comment or
as an external CI artifact for the exact workflow run. Do not add audit
scorecards or one-off validation summaries as tracked Markdown unless a
maintainer explicitly asks for a durable repository artifact.

## Historical Evidence Archive

Historical VPW evidence now lives under `archive/vpw-evidence/`. Important
entrypoints:

- `archive/vpw-evidence/README.md`
- `archive/vpw-evidence/MANIFEST.md`
- `archive/vpw-evidence/final-demo-flow/demo-flow-summary.md`
- `archive/vpw-evidence/final-demo-flow/attack-demo-mapping-summary.md`
- `archive/vpw-evidence/presentation-pack/README.md`
- `archive/vpw-evidence/presentation-pack/evidence-index.md`

The archive now preserves compact demo summaries, presentation-pack references,
selected Markdown evidence, and the retained evidence bundle without making the
public `docs/evidence/` tree or `archive/**` sprawl again.

## Safety Boundary

Reports and evidence may describe CVSS, EPSS, KEV, provider freshness, asset
context, waivers, ATT&CK mappings, and detection coverage. They must not claim
that a local environment was exploited unless a cited source explicitly supports
that statement. ATT&CK context is defensive triage context and does not prove
exploitation.
