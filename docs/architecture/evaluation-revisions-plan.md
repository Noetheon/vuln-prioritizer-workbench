# Evaluation revisions implementation

Status: implemented and locally verified on 2026-09-06. Baseline: `4543bc64`.
Branch: `codex/evaluation-revisions`. Historical evidence and finding identities
remain intact. This records local implementation validation, not a published release.

## Delivery checklist

- [x] One complete pure scope evaluator with explicit policy, facts, observations,
  context, waiver rules and evaluation date; input fingerprint/version.
- [x] Import and asset/waiver paths use this evaluator; score, rationale, context,
  recommendations, governance and ranks agree across paths.
- [x] Persist canonical evaluation inputs in per-finding evidence with bounded
  run-wide metadata; historical v2 rows are unchanged and legacy replay status honest.
- [x] Native queued reevaluation without uploads, including selected provider
  snapshot; preserve observation timestamps and manual work states.
- [x] Append reevaluated evidence to existing Ledger and advance Current atomically.
- [x] Revision preconditions/fencing prevent stale publication after concurrent changes.
- [x] Workflow progress/cancellation visible across real SQLite connections without
  holding a write transaction during parsing/network/CPU work.
- [x] History/diff API and UI; distinct observed/evaluated times and snapshot origin.
- [x] Consistent risk metrics and evidence-owned executive guidance/SLA.
- [x] GitHub preview/export UI and exact action-to-finding scope where appropriate.
- [x] Release input allowlist excludes untracked/private files; mutation patterns checked.
- [x] Incremental evaluation and project ranking measured against 10k baseline.
- [x] Migration, docs, generated OpenAPI client and packaged frontend aligned.
- [x] Focused regressions, backend full gates, frontend gates, real browser flows,
  performance and package checks completed with results recorded.
- [x] Final independent review, clean diff of intended changes, residual limitations documented.

## Ownership during parallel implementation

- Root: decision_core, canonical inputs and shared evaluation, evidence/run revision
  models, migrations, decision_scope_lock, reevaluation service/routes, integration.
- runtime_quality: workflow repository/context/workers and import transaction boundary.
- product_frontend: handwritten frontend/tests, dashboard risk DTO/service,
  run decision summary fields/projection. Generated client coordinated by root.
- decision_architecture: release bundle selector/tests and mutation config/checker/tests;
  then independent review and regression expansion.

## API agreement

- POST `/api/v1/projects/{project_id}/evaluations` accepts optional
  `provider_snapshot_id`, `finding_ids`, `reason`; returns queued `AnalysisRunPublic`.
- GET `/api/v1/projects/{project_id}/evaluations` returns `AnalysisRunsPublic`.
- GET `/api/v1/findings/{finding_id}/decision-revisions` returns paginated
  `{data,count}` with evidence id, analysis_run_id, evaluated_at, observed_at,
  cause, provider_snapshot_id, engine_version, input_sha256, replay_status,
  priority, status, risk_score, operational_rank, rationale, recommended_action,
  is_current and changed_fields.

Project `decision_revision` is a monotonic publication precondition. Mutations
increment it under the existing project lock. Compute captures it before reading
decision inputs and publication compares it under lock. Scope-local evaluation
is separate from project ranking. Existing immutable evidence remains the only
source of decision outputs; canonical inputs are inputs, not another output store.

Full persistent remediation plans and authoritative scan-coverage closure are
the separate next product track, not part of this implementation.

## Final validation

All counts below describe the final relevant runs. Focused suites overlap the
whole-backend suite and are not added to its total.

| Check | Result |
| --- | --- |
| Full backend suite, Python 3.13.5 | 1,334 passed; 4 intentional skips; 137.16 s |
| Backend coverage | 95% overall; 23,478 statements, 1,277 missed; all four critical modules meet their 90% gate |
| Static backend gates | Ruff clean; 450 files formatted; mypy clean across 312 source files |
| Frontend unit tests | 180 passed; 96.68% lines, 86.98% branches, 94.44% functions |
| Frontend lint, type checks and production build | Passed through repository Node/npm wrapper |
| Functional browser suite | 79 passed, including Chromium, mobile Chromium, Firefox and WebKit |
| Design audit | Final macOS 13/13 and canonical Linux container 13/13 passed |
| Generated OpenAPI client | Regeneration produces no drift |
| Packaged frontend | Exact build/resource hash match |
| Documentation | 27 hygiene tests passed; strict MkDocs build passed; local audits excluded from generated site |
| Migration | Upgrade/downgrade preserves pre-revision project and historical JSON; new token starts at zero |
| Source bundle | Allowlist, every member hash, new modules/assets, private-file exclusion and explicit source-manifest roundtrip verified |
| Wheel and sdist | Built from extracted bundle; package contents and Twine checks passed |
| Installed runtime | Fresh offline venv; compatible dependencies; installed `vpw serve`, fresh SQLite migration, HTML/JS/CSS, real import, native evaluation and revision history passed |

The installed test imported `app` from wheel site-packages outside the checkout.
It exercised the supervised worker and verified two immutable revisions, current
selection, retained `observed_at` and unchanged `last_seen_at`. Runtime source hashes
and packaged static bytes matched the source used for the final application tests.
Dependencies came from local caches; four CPython 3.13 packages were reconstructed
as wheels from RECORD-hash-verified existing installations. This is an isolated
local installation test, not proof of fresh public-index dependency resolution.

The first full backend run exposed eleven failures: old report expectations,
historical-schema fixtures, a dependency cycle and missing docs navigation. These
were fixed before the final full run. The combined browser run passed all 79
functional tests but stopped its serial design group at a stale macOS asset
reference. After visual comparison and baseline updates, the complete macOS design
suite passed separately. No screenshot tolerance was relaxed.

Independent review also found and verified fixes for explicitly cleared asset
values being restored, expiry of imported source-file waivers, and incomplete
per-finding provider origin. Additional regressions cover identical-clock revision
ordering, provider tampering, unsupported engine versions, legacy replay conflicts,
manual lifecycle retention, concurrent stale publication and real SQLite
cancellation/lease fencing. Report tests include outer rollback and nested savepoints.

## Measured 10k tradeoff

The existing `VPW-072` fixture imports 10,000 observations into file-backed SQLite,
then adds one finding and checks all 10,001 global ranks. Both measurements use
macOS ARM64 and Python 3.13.5 without coverage instrumentation. These are local
single-run observations, not a statistical performance guarantee.

| Measurement | Audit baseline | Final implementation |
| --- | ---: | ---: |
| Initial import | 12.6379 s | 17.2432 s |
| Incremental import | 33.0684 s | 25.9377 s |
| Tail page, first/repeat | 0.2423 / 0.1564 s | 0.2653 / 0.1672 s |
| Peak process RSS | 397.406 MiB | 445.203 MiB |
| Peak RSS above starting baseline | 266.922 MiB | 313.812 MiB |
| Complete fixture | 46.1138 s | 43.6227 s |

Incremental import is about 21.6% faster in this comparison. The canonical inputs
have a real storage/validation cost: initial import is about 36.4% slower and peak
RSS is higher. All existing 60 s import, 1 s paging and 512 MiB RSS-growth
thresholds pass. The initial implementation had regressed to 44.76 s incremental;
direct enrichment, one scope evaluation and reuse of unchanged decisions removed
that regression. This does not establish the same speedup for large waiver or
native reevaluation workloads; global ranking still considers the whole project.

## Reproduction

From the repository root with its installed development environment:

```bash
.venv/bin/python -m ruff check backend
.venv/bin/python -m ruff format --check backend
.venv/bin/python -m mypy --config-file backend/pyproject.toml backend/app
.venv/bin/python -m pytest backend/tests
.venv/bin/python -m coverage json -o build/coverage-current.json
.venv/bin/python scripts/check_critical_coverage.py build/coverage-current.json
make PYTHON=.venv/bin/python frontend-lint frontend-test-types frontend-test-unit-coverage frontend-build
make PYTHON=.venv/bin/python api-client-drift-check runtime-assets-check
make PYTHON=.venv/bin/python playwright-check-without-design-audit frontend-design-audit
make frontend-design-audit-linux-docker
.venv/bin/python -m pytest -q backend/tests/test_docs_hygiene.py --no-cov
.venv/bin/python -m mkdocs build --strict
VPW_PERFORMANCE_SMOKE=1 VPW_PERFORMANCE_SMOKE_OUTPUT=build/evaluation-revisions-performance-final.json .venv/bin/python -m pytest -q backend/tests/performance/test_vpw072_performance_smoke.py --no-cov
.venv/bin/python scripts/build_release_bundle.py --output build/evaluation-revisions-release
```

Bundle selection intentionally requires new source files to be in the Git index.
An extracted archive instead requires `--source-manifest BUNDLE-MANIFEST.json`.
Use the documented package checks to build/check wheel and sdist and
`scripts/workbench_wheel_smoke.py` for the installed runtime.

## Limits and checks intentionally not claimed

- Historical rows without canonical inputs remain readable but require reimport
  before full replay; no input backfill is fabricated.
- Live provider checks are opt-in and were skipped (three tests). The opt-in 10k
  test was skipped by the broad suite and then passed in its dedicated run.
- Two upstream Starlette deprecation warnings remain; there are no test failures.
- Full mutation execution, dependency-vulnerability refresh and deprecated
  Compose/PostgreSQL deployment parity were not run. Mutation target configuration
  and fail-closed result checking have regression coverage.
- GitHub issue creation was mocked in browser tests. No remote issue, package
  publication or deployment was performed.
- Re-evaluation and simulated risk reduction do not prove remediation. Persistent
  plans and source-aware verified closure remain a separate product track.
