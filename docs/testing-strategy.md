# Testing strategy

Protect the decisions and evidence a local Workbench user relies on. A green
unit suite, a coverage percentage, and a mutation result answer different
questions. Use the smallest relevant check during development, then run the gates
for the affected boundary. This strategy complements the
[current product state](current-product-state.md) and
[delivery record](architecture/testing-quality-delivery.md).

## Risks and checks

| Risk | Primary protection | When and where |
| --- | --- | --- |
| Wrong priority, explanation, missing-evidence fallback or waiver date | Explicit examples, generated policies and boundary properties; focused core mutation testing | `test_scoring`, `test_scope_evaluation`, `property/test_decision_properties`; decision/engine changes |
| Accepting malformed or altered evidence | Valid/invalid SARIF and manifest generators, checksum contracts, evidence mutation testing | `property/test_evidence_properties`; report, bundle and provider-evidence changes |
| Current decisions silently changing old reports | API/worker state machine with an independent lifecycle model and file-backed SQLite | Default backend suite; extended generated sequences in maintenance |
| Aborts/retries publishing partial or duplicate results | Existing durable-worker/concurrency contracts plus generated cancel/retry sequences | Workflow, persistence and evaluation changes |
| Slow reads or excessive storage after many evaluations | Existing 10,000-occurrence import smoke plus repeated history workloads | Changed backend contracts; extended maintenance profile |
| Scanner output, database or SBOM compatibility drifting | Pinned real Grype, fresh isolated DB, offline matching, real HTTP upload/worker/evidence ZIP | Relevant SBOM/scanner changes, weekly and manual runs |
| Losing retained data during recovery or upgrade | CLI restore after hiding the original source; compare recorded decisions and exact report bytes; evaluate again | `recovery-check`, existing migration suite and release path |
| Frontend logic or user journeys breaking | Existing Node unit coverage, selected Playwright workflows and visual checks | Use the frontend npm wrapper; Node unit and Playwright browser runners are distinct |
| Installed artifacts differing from the source checkout | Package contents, wheel migrations/app smoke, existing release readiness | `package-check` and the release workflow |

Tests creating successful work use the real API and worker. Queue acceptance is
not completion: import workflows expose `succeeded`, while native evaluation run
records expose `completed`; their workflow must separately reach `succeeded`.
Retries create a new workflow; the cancelled original stays cancelled.

## Commands and profiles

Activate the configured project environment before using Make. CI's dedicated
quality workflow installs `uv.lock` with `uv sync --locked --all-packages --all-extras`.

| Command | Purpose |
| --- | --- |
| `make check` | Backend formatting, lint, types, tests, and critical line/branch floors |
| `make property-check` | Bounded deterministic generated examples and state sequences |
| `make property-extended-check` | Broader properties and state sequences with the same contracts |
| `make mutation-core-check` | Priority rules/drivers, effective state, clamp, pure scope evaluator and waiver lifecycle |
| `make mutation-evidence-check` | Typed diagnostics, SARIF, manifests, mismatch diagnostics, provider confidence and snapshot helpers |
| `make mutation-check` | Both focused mutation profiles in one fresh campaign |
| `make performance-smoke` | Existing 10,000-occurrence import, incremental import and pagination workload |
| `make history-performance-check` | 200 scopes, three full reevaluation/reimport cycles, 1,400 decision revisions |
| `make history-performance-extended-check` | 1,000 scopes, six cycles, 13,000 decision revisions, compressed historical exports |
| `make recovery-check` | Real retained-history restore plus existing backup and migration regressions |
| `make grype-integration-check` | Download/check pinned scanner, prepare isolated DB, run all three live scanner contracts |
| `make docs-check agent-skills-check` | Published documentation and maintained agent instructions |

The property profile is `VPW_PROPERTY_PROFILE=ci` by default (50 examples; state
machine 8 examples of up to 8 actions). `extended` uses 250 examples; state machine
40 examples of up to 25 actions. Unknown profiles fail. Generated tests are
reproducible for the recorded source and Hypothesis version. Keep minimized real
failures as ordinary regression examples; preserve replay blobs when diagnosing
CI. Example counts are bounds, not claims of exhaustive exploration.

## Mutation evidence and exceptions

`backend/mutation-policy.toml` is the reviewed function selection, checked against
real source definitions. `mutate_only_covered_lines` keeps campaigns practical;
uncovered lines still matter and are checked independently by coverage. The runner
uses the active Python, POSIX forkserver isolation, at most two workers, a 20-minute
campaign limit, and a lock preventing overlapping campaigns in one checkout.

`build/mutation/<profile>/` records source/test/policy hashes, tool versions, commit,
results and logs. A fresh generated tree prevents cached results from masquerading
as a new run. Review the individual survivors; add assertions for observable
behavior. A signal, timeout, skipped mutant, missing pattern or unchecked mutation
fails the gate. None is counted as a killed mutant.

Truly equivalent mutations belong in `backend/mutation-equivalents.json` with a
specific explanation, exact generated mutation hash, and hashes of the source
needed for that argument. Only an observed survivor may match an entry. Changed
source, changed mutations, now-killed entries and infrastructure failures require
review. Report equivalents separately from kills. The initial four entries cover
false-like optional flags and a redundant preliminary rank pass whose output is
replaced by the final pass; they are not broad function exclusions.

Critical modules have independent floors of **90% lines and 80% branches**. The
gate rejects missing, ambiguous and malformed data, including line-only reports.
The authoritative module list is in `scripts/check_critical_coverage.py`.
Coverage is a missing-test signal, not proof of correct behavior.

## History and resource budgets

Use disposable file-backed SQLite, controlled provider snapshots and real
imports/evaluations. Count history rows and observations independently: a
reevaluation adds decisions but must not invent a new observation. At every stage,
current pagination stays bounded and a newly generated original-run report must
retain the same finding evidence.

The first baseline for the new workload on macOS/Apple Silicon measured about
55.8 kB of expanded archive JSON per finding and 11–13.2 kB of allocated SQLite
storage per decision revision. The initial 40 kB report estimate was rejected by
measurement before establishing the limits below. Rich archive evidence has a
different byte budget from the compact current list. The existing 50 MiB plain
report limit remains active: the extended workload uses the already supported
`json-gzip` export, retaining full decompressed evidence.

| Measurement | New history workload ceiling |
| --- | --- |
| Initial import, each reevaluation or reimport | 60 s each |
| Tail page, 100 findings; worst of three reads | 1 s, 1 MiB |
| Historical report generation and download | 30 s |
| Expanded report | 64 KiB per finding |
| Compressed report artifact (extended profile) | 4 KiB per finding |
| Allocated SQLite pages divided by retained revisions | 16,000 bytes per revision |
| Process peak RSS, including the test client | 768 MiB |

The original 10,000-row smoke keeps its existing 60-second initial import,
3-second incremental import, 1-second page and 512 MiB RSS-growth ceilings.
Run performance jobs separately from mutation campaigns on the same machine.
`build/*performance*.json` records datasets, budgets, semantic counts, timings,
bytes, memory and environment even if a workload fails. Budgets are regression
ceilings for these fixtures, not service-level promises for arbitrary evidence or
hardware. Review baseline differences; never automatically relax a failed limit.

## Real scanner and recovery boundaries

The native Grype archive version must match `docker/security-tools/Dockerfile`.
`scripts/grype-checksums.json` holds reviewed release archive SHA-256 pins. Update
both when the scanner changes. Setup creates a private temporary database cache;
matching disables DB and application updates. The test fixture blocks separate
NVD/EPSS/KEV HTTP requests; missing enrichment remains explicitly degraded. This
is a real scanner contract, not a live-provider availability claim.
Only public example SBOMs are processed. Zero findings are a database-dependent
observation, never a timeless safety claim about a package.

The runner records scanner version/hash, DB metadata/hash, API results, evidence
ZIPs and JUnit/logs in `build/grype-integration/`. All three contracts must execute;
a skipped gate is a failure. To replay a retained DB archive, pass
`--db-archive PATH --db-sha256 SHA256` to `scripts/run_grype_integration.py`.
The scanner download still requires the official release host. DB/network setup
failures remain distinguishable from application contract failures.

Recovery tests use an Alembic-created database, real imports and evaluations, a
verified backup, and the CLI restore into a different directory. The original
source is unavailable during the assertion. Current evidence, revision counts and
stored report bytes must survive; regenerating old reports and completing a new
evaluation must still work. Existing damaged-archive and failed-migration tests
protect the recovery failure boundary.

## CI ownership and maintenance

`.github/workflows/test-quality.yml` selects jobs from changed paths, using
`scripts/select_quality_gates.py`; a missing diff selects all gates. Mutation
profiles, properties, performance, recovery and Grype run independently with
`fail-fast: false`, at most three concurrent jobs, explicit timeouts and seven-day
diagnostic artifacts. Docs/UI-only changes skip these backend jobs. Normal CI
continues to run backend checks and frontend checks for their own changed surfaces.
Weekly/manual runs extend generated sequences and retained-history scale.
`maintenance.yml` runs release readiness separately so a Docker/build failure does
not prevent the test-quality campaign. `quality-10-check` remains a legacy local
aggregate name, not a claim that any suite proves "10/10" product quality.

The maintainer of a changed rule owns its examples, properties, mutation selection
and equivalent-mutant review. Authors changing a boundary update this document and
check-selection guidance in the same change. Review weekly failures by cause:
product regression, test/infrastructure failure, or external scanner/provider
change. Do not silently retry until green, suppress unknown survivors, or publish
local measurements as hosted-CI results. Keep distributed chaos, high-concurrency
load and additional mutation frameworks out of this local-first strategy until a
concrete product risk justifies their cost.

Method references: [Hypothesis stateful testing](https://hypothesis.readthedocs.io/en/latest/stateful.html),
[mutmut configuration](https://mutmut.readthedocs.io/en/latest/),
[Grype installation and verification](https://oss.anchore.com/docs/installation/).
