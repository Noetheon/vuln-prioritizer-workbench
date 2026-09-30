# Test quality delivery plan

Status: implementation and local verification complete (2026-09-30). This record is
not a release or hosted-CI success claim. The implementation starts from `b17724ba` (current main on
2026-09-30), with the repository-owned agent guidance preserved separately.

## Objective and acceptance

Protect the decisions a local Workbench user relies on: priority, scoped identity,
current versus recorded evidence, safe workflow publication, and usable retained
history. Prefer observable contracts and independently specified expectations to
assertions that repeat implementation details.

Completion requires every applicable row below to have implementation and fresh
verification evidence. Failures are investigated; expected behavior is not weakened
to obtain a green run. External-service failures remain distinct from offline
regressions. No user database, provider cache, or uploaded evidence is a test fixture.

| Workstream | Planned implementation | Acceptance evidence |
| --- | --- | --- |
| Validator properties | Replace self-comparisons with generated valid/invalid SARIF, manifest, and checksum cases; preserve deterministic errors as a secondary property. | Existing constant-return counterexamples fail; valid examples pass; bounded malformed inputs are rejected without uncontrolled exceptions. |
| Decision properties | Generate supported score/policy combinations, missing evidence, waiver dates, scope inputs, and replay cases. | Explicit expected priority, bounds, provenance, replay, and non-mutation invariants hold. |
| Stateful integration | Generate action sequences through the real API/worker and disposable file-backed SQLite, checking against an independent state model. | Current state follows completed actions; historical reports stay fixed; retries/aborts do not publish partial or duplicate results. |
| Mutation quality | Extend focused mutation scopes to scoring and the pure evaluator, keeping the existing evidence checks; record results and investigate survivors. | Baseline tests pass; every configured scope produces checked mutants; no unreviewed survivor, timeout, skipped result, or infrastructure crash counts as success. |
| Critical coverage | Measure branches and extend explicit critical floors to decision paths. | Missing files/branch data fail closed; useful tests satisfy measured line/branch floors without blanket exclusions. |
| History performance | Exercise repeated imports and reevaluations, reads and reports with accumulated history; measure storage, response bytes, time, and memory. | Explicit reproducible budgets and semantic assertions pass at representative scale; measurements and execution context are saved even on failure. |
| Real Grype integration | Run the existing real scanner/API/worker/evidence flow with a pinned scanner, verified DB setup, offline matching, and recorded provenance. | Vulnerable and zero-observation fixtures run without skips; original inputs and scanner/database hashes survive into evidence. |
| Recovery and release | Reuse migration, backup/restore and installed-runtime checks, adding contract gaps demonstrated by inspection. | Retained decisions/artifacts survive recovery and supported upgrade paths; source data remains recoverable on failure. |
| CI and maintenance | Keep cheap offline checks in PRs, scope expensive checks to affected code, and run extended mutation/history/scanner jobs independently on a schedule. | Selection and failure behavior are tested; jobs have explicit time/resource bounds and retain actionable reports. |
| Documentation | Maintain risk-to-test mapping, commands, profiles, budgets, exception policy, and ownership alongside code. | Docs and repository-guidance checks pass; recorded results distinguish local execution from hosted CI. |

## Sequence

1. Recheck affected contracts on the current main branch and establish the working
   Python/tool versions. Record the baseline and the concrete negative controls.
2. Strengthen pure properties and decision tests. Demonstrate that the previously
   surviving constant implementations are detected before enlarging mutation scope.
3. Add generated API state sequences and recovery coverage using existing harnesses.
4. Run focused mutation campaigns, review individual survivors, and add tests for
   missing behavior. Handle semantically equivalent changes explicitly with a
   narrow explanation rather than a misleading global mutation percentage.
5. Measure history workloads before choosing portable ceilings. Establish a small
   reproducible regression workload plus an extended scheduled workload.
6. Wire independent CI jobs and the real scanner gate, with explicit input pins,
   bounded setup, diagnostic artifacts, and no hidden live-network requirement in
   ordinary tests.
7. Run relevant backend, property, mutation, performance, recovery, workflow,
   documentation, and instruction gates; inspect the final diff and update this
   record with measured outcomes and remaining external validation boundaries.

## Resource and maintenance policy

- Default generated tests use bounded deterministic examples; the extended profile
  increases breadth without changing the asserted contracts. Retain minimized
  counterexamples as ordinary regression cases when they identify a real defect.
- Prefer file-backed SQLite and controlled time/provider evidence for lifecycle
  tests. Genuine network/provider/scanner drift is a separate named job.
- Mutation results apply only to their declared source and function selection.
  Uncovered code is assessed by coverage; infrastructure failures are not kills.
- Performance budgets must be attached to dataset size and operation count.
  Absolute limits catch unusable behavior; normalized byte/count measures catch
  growth even on a fast machine. Do not loosen limits automatically.
- Keep the installed runtime, data migration, and restore checks in the release
  route. Reuse the real product boundary rather than a synthetic success stub.
- The maintainer of a changed rule owns its example/property expectations and
  mutation selection. CI scripts and their selection logic have regression tests.
- Broad distributed chaos, large concurrent-user load, formal verification and a
  new frontend mutation framework are outside this local-first test improvement.

## Execution record

- Goal created and working branch isolated: complete.
- Initial review reproduced three validator properties accepting constant results.
- Replaced the three self-comparison validator properties; all three original
  constant-return negative controls are now detected (`build/property-negative-controls.json`).
- Found and fixed a production SARIF defect: null/non-array `runs`, `rules` and
  `results` previously raised `TypeError` after schema validation. They now produce
  validation errors; minimized ordinary examples and generated variants pass.
- Added generated policy, waiver and replay properties and a real API/worker
  lifecycle state machine. The extended profile passes 37 tests, including up to
  40 generated sequences of 25 actions (310.80 seconds in this concurrent local run).
- Focused mutation campaigns on Python 3.13 and the locked Python 3.14 environment
  both pass: 378 selected mutations, 374 killed and four individually reviewed
  equivalents. No unreviewed survivor or infrastructure result is accepted.
  Source and selected-test hashes match the current checkout.
- Real Grype 0.119.0: all three CycloneDX/SPDX/zero-observation contracts executed
  without skips. The positive fixtures include CVE-2021-44228. Original SBOM hashes,
  scanner version and actual DB checksum survive into exported evidence. Separate
  provider HTTP is deliberately blocked and missing enrichment stays degraded.
- Recovery gate: 22 tests passed, including real import/evaluation history restored
  through the CLI after moving the original source out of reach; retained report
  bytes, historical regeneration and a new evaluation all remain valid.
- 10,000-occurrence smoke: initial import 27.84 s, incremental import 1.27 s,
  tail page 0.15 s, process peak RSS growth 255.08 MiB; existing ceilings unchanged.
- History CI profile: 1,400 decision revisions, 13.12 s total, worst tail page
  0.065 s, 186,246-byte page, 252.03 MiB process peak RSS.
- History extended profile: 13,000 revisions and 7,000 observations; about 132 MB
  allocated SQLite pages, worst tail page 0.104 s, 186,512-byte page; largest
  historical gzip artifact 2,583,173 bytes (55,623,118 bytes expanded); report
  generation/download at most 6.13 s; 731.22 MiB process peak RSS; 119.17 s total.
  Full recorded finding evidence is compared on each cycle.
- The same extended history workload also passes with the locked CI interpreter,
  Python 3.14.6: 13,000 revisions, worst tail page 0.068 s, report generation/download
  at most 6.52 s, 646.16 MiB process peak RSS and 120.39 s total. The same resource
  ceilings and retained-evidence comparisons apply.
- Calibration: the initially estimated 40 kB per expanded finding was below the
  existing approximately 55.8 kB representation; the reviewed ceiling is 64 KiB.
  The existing 50 MiB plain-report limit correctly rejected the 1,000-finding
  export, so the extended workload uses the supported gzip format. A large
  temporary JSON copy in the test's comparison initially exceeded the 768 MiB
  memory ceiling. Incremental hashing removed that copy; the ceiling was kept.
- Critical coverage now measures lines and branches separately for eight modules.
  Additional provider-diagnostic boundary tests cover structured and legacy errors.
- Independent CI jobs include scoped mutation profiles, generated properties,
  performance, recovery and scanner matching with bounded resources and artifacts.
  Reproducing the CI install caught that workspace dependencies require
  `uv sync --locked --all-packages --all-extras`; the workflow now uses that command.
- Python 3.14 locked-environment focused contracts: 67 tests passed. Final targeted
  checks pass for all 11 CI-selection cases and all 26 mutation/scanner-runner cases,
  including refusal to reuse a mutant tree when fresh cleanup fails.
- Backend formatting/lint and mypy (354 source files) pass. Documentation, lock
  exports, release-evidence hygiene and agent-guidance checks pass. Native
  actionlint 1.7.12 and action SHA-pin validation pass.
- sdist/wheel build, package contents, Twine validation and an isolated installed
  wheel migration/app smoke pass. The installed package was verified to load from
  its isolated environment, not the source checkout.
- Full backend gate: 1,734 tests passed, eight opt-in tests skipped, six warnings
  (406.04 s). Scanner and performance opt-ins were exercised separately as recorded
  above; live external-provider checks were not run. All eight critical modules
  satisfy the 90% line and 80% branch floors. The final CI-selection and runner
  cleanup additions were checked separately after this full-suite run.
- Final diff whitespace and pre-commit checks pass. No schema migration or runtime
  dependency change is introduced; the only production behavior change is bounded
  handling of malformed SARIF containers.

These measurements come from the local macOS/Apple Silicon checkout with Python
3.13.5 unless stated otherwise; they are not hosted Linux CI results. The Docker
daemon is unavailable locally, so native actionlint was used for workflow syntax.
The existing Docker/browser/release rehearsal was not rerun for this backend-test
change. Its independent release job remains configured; no release was published.
Local logs, hashes and JSON/JUnit evidence are under `build/` and intentionally
excluded from the source package and Git. The maintained strategy is
[Testing strategy](../testing-strategy.md).
