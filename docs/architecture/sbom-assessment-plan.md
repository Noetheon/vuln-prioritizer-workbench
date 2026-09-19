# Local SBOM vulnerability assessments

## Objective and boundaries

An explicit SBOM upload can run a local Grype vulnerability assessment and feed
the existing scope-first prioritization and Decision Ledger. Scanner-report
imports remain available. The scanner only reads the uploaded inventory; this
does not observe a deployed system or prove runtime exploitability.

## Design decisions

- Use one optional, configured native Grype executable. Never execute uploaded
  commands, install a binary during an HTTP request, or inherit ambient scanner
  ignore/configuration files. Manage the scanner database separately from the
  Workbench provider snapshots.
- Keep the original SBOM and scanner JSON as immutable managed artifacts, with
  hashes and a typed `sbom-assessment.v1` manifest in AnalysisEvidenceV2. Keep
  successful workflow results as compact `workflow-result-ref.v2` references.
- Bind findings to a stable SBOM subject, not a temporary filename. Preserve
  scanner advisory identifiers and resolve real match-level CVE aliases.
- Distinguish successful zero matches, partially usable reports, malformed
  input, unsupported inventory and scanner failures. Record scanner matches,
  prioritized CVE matches and unresolved advisory matches separately.
- Retain all inventory in the original SBOM. A new dependency-graph database is
  unnecessary for this bounded feature. Identification counts do not imply
  complete scanner coverage.
- A rescan appends a new assessment of the retained inventory. Preserve its
  observation time independently from scan/evaluation time. Missing matches do
  not close existing findings automatically.
- Run subprocess work in the existing durable worker, with bounded output,
  timeout, cancellation, shutdown and lease ownership checks. Publication stays
  transactional and fenced by project revision.

## Implementation and validation sequence

- [x] Correct scanner normalization with official-schema regression fixtures.
- [x] Implement strict SBOM inspection and supervised Grype adapter; test
  timeout, cancellation, missing executable/database, malformed and empty output.
- [x] Add explicit upload options and typed assessment evidence; integrate
  positive, zero and partial results into the existing import workflow.
- [x] Preserve raw artifacts and hashes in downloadable scan evidence.
- [x] Add a rescan endpoint with immutable lineage and observation timestamps.
- [x] Add upload controls, assessment diagnostics and rescan UI; regenerate the
  OpenAPI client and verify API/UI parity.
- [x] Test the full API workflow with deterministic fixtures, including aliases,
  no matches, unresolved advisories, stable identity, retries and cancellation.
- [x] Run real Grype against representative local CycloneDX/SPDX examples with
  a recorded executable and database version. No private inventory is uploaded.
- [x] Run relevant backend/frontend/docs/type/lint and browser checks.
- [x] Independently review implementation, fix findings and record final checks.

## Acceptance evidence

Validation date: 2026-09-19. Fixture-based tests establish application behavior;
real scanner examples establish the selected version's integration. Neither is
a universal completeness or exploitability claim.

The official immutable Grype 0.110.0 Darwin/arm64 release was downloaded only
to ignored `build/sbom-tools/`, with its archive verified against both the
release API digest and official checksum manifest. No system install was made.

| Evidence | Recorded value |
| --- | --- |
| Release archive SHA256 | `9aff01bfcb4510a1b803ef59375b43cd80764fa49aed71f9a3da81c417037411` |
| Executable SHA256 | `647df9e201f59725bf68aefe82b2fd395c5fd0979edf929e5a32065f16382cfa` |
| Grype database built | `2026-09-18T06:30:15Z` |
| Database schema | `v6.1.9` |
| Database file SHA256 | `e16745f65254ac5f04d785db64be8b96f32c2828c153cbcbe15dcedcbbf0956f` |

Both vulnerable examples (lodash 4.17.20 and log4j-core 2.14.1) produced 12
matches and 12 prioritized findings. The is-number 7.0.0 example produced a
successful zero-match, zero-finding assessment. All three passed through the
real HTTP upload, durable worker, Ledger and verified ZIP download in
`backend/tests/live/test_sbom_live_contract.py`. Grype DB updates were disabled
during those tests. Providers used the demo snapshot: the vulnerable runs
correctly recorded degraded provider coverage; this is not a live-provider test.

Local detailed records are in `build/sbom-tools/download-verification.json`,
`build/sbom-validation/validation-results.json`, the `*.api-result.json` files
and the `*.evidence.zip` files. These ignored build artifacts are not release
inputs. Small reusable inventories are source examples under
`docs/examples/sbom-*`; see [operator instructions](../sbom-assessment.md).

Independent reviews found and fixed these concrete issues:

- Queued imports could be claimed before scanner options were committed.
  Payload and upload receipt now become visible atomically; a file-backed
  SQLite test claims the workflow from an independent session immediately
  after the first commit.
- A changed on-disk input could disagree with the prepared hash. Worker reads
  and scanner publication now verify integrity; mismatched declared formats
  also fail before successful evidence publication.
- Assigning UTC to an aware datetime shifted its instant. Observation times
  are now converted correctly, and rescans retain source observation time.
- Scanner/parser warnings could expose paths or grow with every advisory.
  Public evidence sanitizes and bounds warnings while retaining the raw report.
- The real browser run exposed macOS symlinked upload roots (`/var` versus
  `/private/var`) producing invalid relative artifact references. The root is
  now resolved consistently, with separate symlink and relative-path tests.
- A report declaring an invalid database could appear complete. Explicit
  database invalidity now fails; incomplete package evidence remains partial.

The scanner/process, rescan/ZIP, timestamp, sidecar, report and frontend slices
received separate review. The final quality-gate record is completed below.

## Final quality gates

| Gate | Result |
| --- | --- |
| `make check` | 1,413 tests passed; 7 opt-in tests skipped; Ruff format/lint and mypy (320 source files) passed. |
| Backend coverage | 94.51% statements; critical gate passed for all 4 protected modules at >=90%. |
| `make frontend-check` | Passed using the existing offline npm cache after registry timeouts; lint, production build, runtime assets, types, unit coverage and regenerated-client drift checks passed. |
| Frontend unit tests | 186 passed; 96.78% lines, 87.28% branches, 94.47% functions. |
| Import Playwright tests | 15 passed (12 existing import flows plus 3 SBOM upload/partial/download/rescan flows). |
| Real Grype API gate | 3 passed: CycloneDX and SPDX with 12 findings each, plus zero-match CycloneDX; verified raw-evidence ZIPs. |
| Real browser against packaged UI and backend | Vulnerable and zero-match SBOM uploads completed through the in-process worker and real Grype; evidence ZIPs downloaded and verified; no browser errors. |
| Docs | 27 hygiene tests and `make docs-check` passed, including MkDocs and release/archive evidence hygiene. |
| Release bundle selection | 15 release-bundle tests passed with the new generated assets and source files in the Git index. |
| Whitespace | `git diff --check` and staged-diff check passed. |

The seven normal-suite skips are three live-provider checks, three real-Grype
checks and the optional scale smoke. The three real-Grype checks were run
separately with the recorded binary/database. No Docker/PostgreSQL or Windows
validation, broad live-provider availability certification, or scale benchmark
is claimed. The live browser's vulnerable case used unlocked provider fallback
and could fetch missing provider data; it is distinct from the request-blocked
deterministic API tests. Scanner database downloads were off in both cases.

Detailed current logs are local build artifacts:
`build/sbom-validation/backend-check.log`, `docs-check.log`, the browser evidence
directories and frontend validation records. All implementation changes are
on `codex/local-sbom-assessment`; no push, merge or release was performed.

## Starting state

The working tree already contains unrelated dependency, CI and Decision Ledger
changes. Preserve them. The existing Grype importer reads CVE aliases from an
incorrect nesting level; empty CVE collections are rejected by both input and
analysis stages. The current runtime has no scanner subprocess supervision.
