# Decision storage and scalable current views

Status: implementation in progress. Baseline: `0d654697effc07e3774429b43972c23b7e0ef468`.

## Decision

Separate the current queue from immutable historical decisions. Keep the shared
pure evaluator, explicit evaluation inputs, provider provenance and the project
publication fence. A current rank is presentation state; moving a peer in the
queue must not duplicate its decision evidence or imply a new evaluation.

The independent review confirmed write amplification, evidence-heavy reads,
history scans during import and unbounded report construction. It did not justify
discarding decision history, changing the scoring policy, or treating a mean risk
score as a mathematical error. Those are not part of this implementation.

## Required guarantees

- Historical run results remain immutable and independently exportable, including
  the engine, inputs, provider provenance and rank recorded at evaluation time.
- Current list, detail, dashboard and reports agree on decision semantics.
- A scope identity cannot silently merge assets, targets, components or CVEs.
- A concurrent input change invalidates an in-flight publication.
- Waiver expiration has an explicit owner and observable freshness; removing GET
  writes must never silently present expired acceptance as current.
- Storage migration preserves existing evidence and rejects unsupported schema
  states. No production data is used by development benchmarks.

## Delivery sequence

1. **Queue ownership.** Materialize compact canonical sort keys, update only rank
   columns for displaced peers, derive rank-dependent wording when reading current
   evidence, and keep rank-only changes out of evaluation history.
2. **Read models.** Make list responses compact, load detailed evidence on demand,
   and compute dashboard aggregates from bounded query/read models. Regenerate the
   API client and update UI consumers and packaged assets.
3. **Input changes.** Evaluate only affected scopes for waivers/assets and reuse
   unchanged decisions during import. Move day-boundary maintenance to the worker
   with explicit freshness semantics. Avoid repeated asset-history scans while
   preserving identity collision checks.
4. **Immutable storage.** Share repeated immutable evidence/provider data, hydrate
   through one repository boundary, migrate old rows and verify exact historical
   payload round trips and corruption detection.
5. **Operational boundaries.** Bound report construction and serialization, make
   size failures predictable, and validate required schema columns at startup.
6. **Acceptance.** Run semantic contract suites, migration/backup tests, frontend
   and documentation gates; repeat the offline workload and publish measured
   before/after results, remaining limits and operational instructions.

Each step is a reviewable commit. Tests for replaced mechanisms are replaced by
behavioral and work-budget assertions before obsolete implementation is removed.

## Acceptance criteria

- Adding one scope performs no historical evidence writes for existing peers and
  no full evidence overlay writes solely to change rank.
- A waiver affecting one scope creates at most one decision revision for that
  scope; unrelated peers can change current rank without new decision evidence.
- List response size and dashboard read volume do not scale with full evidence
  size. Detailed evidence remains available through the detail contract.
- Identical reimports do not repeatedly copy large unchanged evidence sections;
  identity checks do not rescan an asset's entire history per occurrence.
- GET requests do not commit decision mutations; freshness and expiration are
  covered by worker and API tests.
- Report generation uses bounded memory and enforces limits while producing data,
  not after building another complete copy in memory.
- Existing databases migrate, source hashes and historical reports remain valid,
  and invalid/incomplete schemas fail explicitly.
- Performance evidence records dataset, snapshot digest, database size, wall/CPU
  time, peak memory and workload semantics. Deterministic work/byte budgets guard
  CI; machine-specific timing targets are calibrated from measured results.

## Baseline

The offline API/worker probe used 1,000 and 5,000 scopes, four CVEs and a fixed
provider snapshot. At 5,000 scopes: initial import 19.4 s; repeated imports 43.9 s
and 59.4 s; one additional scope 61.3 s; one-scope waiver 133.3 s; dashboard
18.0–29.0 s. A repeated import added about 223 MiB. A 100-row list was about
4.6 MB. The additional scope rewrote all existing projections; the one-scope
waiver created 5,000 evidence revisions. Timings are observations on a busy
16-GiB laptop, not portable CI thresholds.

The full baseline and reproducible probes are retained in the task artifact
`vpw-independent-review`. This plan will be completed with repository-owned
verification and measured results as implementation proceeds.

## Implemented slices

- Current rank updates use compact sort keys and executemany column updates.
  Historical payload hashes and lifecycle overlays do not change for displaced
  peers. Current detail wording adapts its top-five prefix without reevaluation.
- Governance synchronization compares compact input state before hydrating a
  scope. A one-scope waiver evaluates and publishes one scope; queue peers retain
  their original evidence. Native selected reevaluations follow the same rule.
- Finding lists default to compact current columns and a recorded `sla` summary.
  `include_evidence=true` explicitly expands a page; the finding detail endpoint
  still returns the full evidence contract. The frontend reads the compact SLA.
- Dashboard aggregates consume the same compact read model. Full evidence remains
  available for historical reports and detailed explanations. Summary migration
  tests cover exact history preservation, failure rollback and successful retry.
- Historical decisions share immutable, compressed JSON sections within their
  project. Provider facts are shared across scopes and repeated imports. A single
  repository boundary reconstructs the unchanged v2 contract and checks both
  section and complete-payload hashes; missing/corrupt content fails explicitly.
  The transactional migration verifies every reconstructed payload before replacing
  its storage document. Downgrade restores standalone JSON. Project deletion
  cascades to shared sections; sections otherwise live as long as project history.
- Asset collision checks read distinct identity fields through a covering index,
  and summarize them once per asset during the read-only import preflight.
  Reimports no longer deserialize every past observation for every finding. The
  index follows the original JSON, including contradictory legacy facts; there is
  no second mutable identity certificate. A work-budget test covers repeated
  shared-asset imports, use of the index, and detection of an altered old fact.
- Startup and readiness validate all required columns, including nullable ones,
  and require exactly the supported migration head. Missing tables in a populated
  or unknown schema are not silently recreated/stamped. Supported legacy table
  rebuilds are transactional, preserve child foreign-key targets, restore SQLite
  pragmas on failure and recreate expression indexes correctly.
- The workflow worker owns UTC-day governance maintenance, with the existing
  atomic project publication fence. GETs do not claim or commit refreshes. Current
  decisions return `503 decision_refresh_pending` with `Retry-After: 2` until a
  stale project is refreshed; project metadata, history and reports stay readable.
  Failed projects roll back and retry independently on a later worker tick. The
  frontend invalidates open views at the UTC day boundary and polls only this
  pending condition until current decisions are available.

- JSON and CSV exports stream immutable evidence in batches of 25. The explicit
  `json-gzip` format preserves the complete JSON contract for larger runs. Size
  limits apply during output; compressed exports also have an expanded-byte cap.
  Other renderers reject oversized inputs during batched construction. Historical
  membership, redaction, rollback cleanup and publication fencing remain shared.

Validation so far: 233 baseline import/report/workflow contracts; 200 tests after
queue/governance changes; 155 import/compact-read contracts after the list change;
186 frontend unit tests and frontend typechecking. These are slice checks, not
the final acceptance run. Storage sharing adds corruption, project-isolation,
transaction rollback and reversible-migration coverage; 83 storage, revision,
workflow and report contracts pass after integration. Reports, complete gates and
final measurements remain in progress. The asset
change passes 178 import/migration contracts and its targeted read-budget check.
Schema/startup validation passes 68 tests, including injected copy failure and
rejection of missing columns, missing history and unknown schema revisions.
Temporal maintenance passes 74 revision/workflow/waiver contracts plus a targeted
failure-isolation/retry test. Frontend coverage remains above the configured gates.

### Daily maintenance operations

`vpw serve` runs maintenance in its in-process worker. Deployments with an external
worker must keep it running even when no imports/reports are queued. A pending
current view does not itself enqueue or perform a write. A persistent
`decision_refresh_pending` response means the project's daily maintenance has not
committed: check worker health and its `Daily decision refresh failed` log before
retrying. Successful refreshes retain immutable evaluation revisions and the
`waiver.lifecycle_refresh` audit event. Historical reports remain available during
this condition. A project without findings can still return an empty current view.

### Storage migration operations

Back up the complete database before upgrading, as for any schema migration.
Migration `20260923_0014` processes evidence in batches of 100 inside one
transaction. Preserve enough disk space for the migration journal/WAL and a
rollback; compression does not immediately shrink an existing SQLite file. Freed
pages are reusable by subsequent writes. Historical JSON values and canonical
hashes are preserved, although physical JSON ordering and on-disk representation
change. The section encoding is versioned independently of the public contract;
keep its v1 decoder available for old data and migration rollback.

### Reproducing the workload

With the repository's development Python dependencies installed:

```sh
python scripts/benchmark_decision_storage.py --rows 1000 --output build/decision-storage
python scripts/benchmark_decision_storage.py --rows 5000 --output build/decision-storage
```

Each invocation creates and removes its own SQLite database, blocks provider
HTTP requests and uses the fixed demo snapshot. JSON results identify the source
commit, tracked diff, probe, input and snapshot hashes. They record wall/CPU time,
SQL/history work, database/section sizes and cumulative process peak RSS. The
pure-evaluator experiment intentionally loads all inputs; its cumulative RSS must
not be interpreted as the streaming report's isolated peak. Run scales sequentially
without concurrent test/build workloads when comparing timings.

Normal CI tests guard semantic work budgets: displaced peers retain history and
overlays, unchanged queue reads avoid hydration, one-scope waivers create one
revision, repeated sections do not grow, asset proofs use indexed distinct facts,
and report readers stop at a fixed batch/input budget. The optional 10k performance
smoke reduces the one-additional-finding allowance from 60 to 3 seconds. Initial
import and memory ceilings remain hardware-sensitive smoke limits; they do not
replace the deterministic work/byte guards.
