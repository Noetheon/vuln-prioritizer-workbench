# Decision Ledger Architecture

This document defines the current decision persistence contract. It separates
historical evidence from the mutable state needed by the Workbench UI and
operational queries.

## Invariants

VPW stores two deliberately different views of a finding decision:

| Store | Purpose | Mutation rule |
| --- | --- | --- |
| `analysis_evidence` | Typed, run-wide `AnalysisEvidenceV2` and diagnostics | An empty envelope may be prepared for chunked persistence; after finalization, the payload is immutable. |
| `finding_decision_evidence` | One `FindingDecisionEvidenceV2` source record per finding and analysis run | Append-only. A retry may reuse an identical row but cannot rewrite it. |
| `finding_current_projection` | One queryable current row per finding | Materialized query columns plus a sparse mutable lifecycle overlay. A newer run advances the immutable source; lifecycle actions update only this row. |
| `audit_event`, `waiver`, workflow events | Lifecycle and governance history | Existing append/audit contracts remain the historical record for status, waiver, and workflow actions. |

Historical run reads and run-specific reports always use the immutable run
evidence. Current dashboard, finding-list, detail, governance, waiver, and
GitHub-preview paths use the current projection. Relational `finding` columns
remain identity and join anchors; they are not a second decision source.

## Atomic Write Path

Successful imports first validate typed Decision/Evidence Kernel contracts.
Within the same database transaction they then:

1. append each per-run `finding_decision_evidence` row;
2. insert or advance the corresponding `finding_current_projection` row;
3. finalize the run-wide `analysis_evidence` payload;
4. commit workflow and run state only after persistence succeeds.

The normal repository and the bulk-import path share this dual-write contract.
A source record that is older than the current projection cannot move current
state backwards. Repeating the same source is idempotent and must preserve the
same canonical hash.

Status changes, waiver synchronization, and asset-driven lifecycle updates
mutate the current projection only. They increment `revision` and
`lifecycle_revision`; they do not alter the source payload or its hash.

The projection intentionally does not store a second copy of the full finding
payload. The effective current contract is reconstructed from the immutable
source and a sparse top-level lifecycle overlay, then validated as
`FindingDecisionEvidenceV2`. This keeps large imports bounded while retaining
an independently hashable current state.

## Provenance And Parity

Each current projection records:

- the source run and source evidence row;
- the source timestamp;
- a canonical SHA-256 of the immutable source payload;
- a canonical SHA-256 of the effective current payload;
- a sparse lifecycle overlay (empty while current state equals its source);
- projection and lifecycle revision counters;
- denormalized columns used for filtering, sorting, and pagination.

Complete parity verification checks all of the following:

- every historical finding with evidence has one current projection;
- the source row still exists and has matching finding, project, and run IDs;
- the projection source timestamp matches the immutable source row;
- the source payload matches its recorded SHA-256;
- source plus lifecycle overlay reconstructs a valid current payload;
- the reconstructed current payload matches its own SHA-256;
- before lifecycle mutation, the overlay is empty and source/current hashes match;
- the validated current payload matches every materialized query column.

Normal reads shadow-check a bounded sample of the projections they already
loaded, controlled by `DECISION_LEDGER_SHADOW_SAMPLE_SIZE`; they do not run a
global coverage scan. Mismatches are logged by default and may be made fatal
with `DECISION_LEDGER_STRICT_PARITY=true`. Explicit maintenance checks add the
complete history/projection coverage check and scan every projection in bounded
keyset batches:

```bash
vpw ledger verify --strict --data-dir ./vpw-data
```

## Migration And Backfill

Alembic revision `20260710_0004` creates the current projection and backfills
the newest persisted evidence row for each finding with an empty lifecycle
overlay. Existing v1.2 lifecycle state is retained because that state was
already represented in the newest legacy evidence payload when the migration
runs.

The repository backfill is idempotent and bounded:

```bash
vpw ledger backfill --data-dir ./vpw-data
```

It only inserts missing current rows. It never rewrites historical evidence or
replaces a newer projection with an older source.

## Query Contract

Current finding pages filter, sort, count, and paginate in SQL over
`finding_current_projection`, joined to finding identity, asset, and component
tables. The indexed projection supports operational rank, priority, status,
KEV, EPSS, CVSS, and risk-score paths without scanning every historical run in
Python.

Run-specific reports and evidence views remain bound to the selected immutable
run. This prevents a later status or waiver action from silently changing a
previously completed run's evidence.

## Failure And Recovery

Dual writes use one transaction, so a failure cannot commit history without
its current projection or vice versa. A failed shadow check does not
automatically overwrite either side. Operators should preserve the database,
run strict verification, and investigate the named source, hash, payload, or
materialized-column mismatch.

Cross-database migration also requires complete Ledger parity on both source
and target before activating the new SQLite database. See the
[single-process runtime transition](../single-process-runtime-transition.md).
