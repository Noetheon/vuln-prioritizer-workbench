# Sustainable quality delivery

Status: implemented; local validation recorded below. Hosted activation is verified
through the PR checks and the live GitHub protection/health audit, not this static file.

This follow-up makes the [testing strategy](../testing-strategy.md) enforceable
over time, building on the locally verified test work and main including PR #699.

| Requirement | Acceptance |
| --- | --- |
| Required admission | Selected contracts produce fresh evidence; missing/failed/skipped results fail admission. Main requires the gate without weakening existing protections. |
| Policy review | Source-bound reasons cover policy/budget/exemption changes, removed tests and new critical entry points. Future PRs use the base-branch checker. |
| Regression discipline | PR/bug templates and guidance require independent expectations, red/green reproduction or a bounded exception, owner and repair deadline. |
| Exploration | Scheduled/manual seeds vary by execution and are retained for replay; PRs remain deterministic. |
| Trends | Compact metrics survive 90 days; comparability, calibration, scope reduction, budget proximity and sustained deterioration have negative tests. |
| Monitoring | Daily read-only checks detect stale/failed/disabled campaigns; an independent Codex heartbeat also checks protection drift. |
| Release | Candidate builds depend on the reusable quality workflow for their own commit; existing release checks remain. |

## Verification record

- Existing protection inspected: five required checks, strict updates and enforced
  administrators; no required human approval. This rollout adds machine admission
  and does not invent an independent human reviewer.
- Implementation is isolated in the existing managed worktree.
- Focused admission/policy/monitoring validation: 57 tests passed. Temporary
  Git fixture creation was removed so host-specific Git hooks cannot change the
  policy unit-test result; the actual current-tree Git comparison is also checked.
- Two additional negative controls exposed missing review of new methods on
  existing critical classes and Git read failures treated as absent base files.
  Both tests fail before the corrections and pass afterward.
- Existing package/tooling negative contracts: 40 tests passed.
- Real recovery execution through the new runner: 22 tests passed and a fresh
  successful receipt was verified.
- Full backend validation after the evidence-copy optimization: 1,785 tests
  passed, eight optional checks skipped; types and all eight critical coverage
  floors passed. Two additional import-trend controls passed in the focused suite.
- All six contract runners passed locally: core 208 killed plus four reviewed
  equivalent mutations; evidence 166 killed; 37 extended generated tests with a
  recorded seed; recovery 22; history with 13,000 revisions; three real Grype
  contracts. Receipt aggregation passed and the empty historical baseline was
  correctly reported as calibrating. These are local execution results.
- Native actionlint, action pins, formatting/lint, pre-commit, docs and project
  guidance checks pass. Source-bound adoption reasoning covers the affected files.
- Hosted checks and branch protection are authoritative for activation. See the
  [delivery PR](https://github.com/Noetheon/vuln-prioritizer-workbench/pulls?q=is%3Apr+head%3Acodex%2Ftest-quality-strategy)
  and [quality runs](https://github.com/Noetheon/vuln-prioritizer-workbench/actions/workflows/test-quality.yml).
- Independent daily Codex heartbeat created and verified active. The host's
  global privacy guard initially rejected existing upstream commit metadata.
  After the upstream history was independently cleaned, only this delivery's
  unpublished commits were transferred onto the clean base. The new publication
  privacy guidance was retained alongside project guidance. The guard remains
  active. Hosted checks and branch protection establish activation separately.
- A recheck of the earlier main maintenance campaign passed 105 browser cases
  and failed one responsive navigation case; its old artifact configuration
  omitted browser diagnostics. The focused case passed locally. First-attempt
  failure traces, route/viewport step labels and retained maintenance browser
  artifacts now make a recurrence diagnosable without relaxing assertions.
- The next maintenance run reproduced the late responsive navigation failure
  and reported ENOSPC while closing the browser trace. The 63 route/viewport
  combinations now run as seven independent viewport cases with bounded browser
  contexts and traces. All 12 responsive cases passed locally; runner disk/Docker
  capacity is also retained in maintenance logs.
- The hosted recheck passed every responsive case and retained six GiB of free
  runner disk space. It exposed a separate accessibility fixture race: a fixed
  500 ms response could end the busy state before an assertion or during the
  accessibility audit. Both findings-loading tests now hold the mock response
  until assertions finish and verify the subsequent ready state. Restoring the
  old 500 ms behavior fails the added post-audit loading assertion; the response
  barrier passes all 27 cases in the two owning browser suites. The testing guide
  records this fixture rule. Hosted release validation must verify the final candidate.
- The first hosted quality campaign rejected a 10,000-entry import taking
  62.3 seconds against the existing 60-second limit. Profiling identified eager
  copies of large sections immediately removed by evidence encoding. Detaching
  only edited containers before copying retained values preserves the storage
  format and integrity checks. The focused storage/property suite passed 38
  cases; the local full-size import measured 26.0 seconds after the change.
  Local and hosted timings are distinct measurements, not a cross-machine
  speedup claim. The next hosted import measured 57.7 seconds and the history
  contract passed, without changing its 60-second limit. Import metrics now also
  warn at 90% of budget and on sustained deterioration; two red/green controls
  verify these warnings and prevent comparison across different import sizes.

These are separate outcomes. No release or package publication is part of this rollout.
