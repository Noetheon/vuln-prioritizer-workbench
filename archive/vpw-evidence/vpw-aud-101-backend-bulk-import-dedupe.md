# VPW-AUD-101 Backend Bulk Import Dedupe Evidence

Issue: VPW-AUD-101 / #399
Category: Backend/API
Date: 2026-05-07
Disposition: gap

## Scope

This evidence covers same-batch duplicate finding dedup keys in the Workbench
bulk import persistence path. The change is limited to detecting duplicate
incoming dedup keys before the large all-new bulk insert path is used.

Out of scope: importer redesign, parser contract changes, and generated client
changes.

## Behavior Verified

- A 1000-row generic occurrence CSV batch with the same CVE and asset identity
  succeeds without violating the `project_id` plus `dedup_key` uniqueness
  constraint.
- The import persists one Finding and 1000 FindingOccurrence rows.
- Summary semantics are preserved:
  - `occurrence_count=1000`
  - `finding_count=1`
  - `created_findings=1`
  - `updated_findings=999`
  - `reused_findings=999`
- Dedup decision sampling still records 500 sampled decisions and reports 500
  omitted decisions.
- Existing DB-to-import dedupe behavior remains covered by the import API test
  suite.

## Validation Commands

```text
python3 -m pytest -q backend/tests/api/test_template_import_upload_api.py::test_same_batch_duplicate_bulk_import_reuses_finding_and_appends_occurrences --no-cov
```

Result: `1 passed in 2.18s`

```text
python3 -m pytest -q backend/tests/api/test_template_import_upload_api.py backend/tests/api/test_template_service_layer.py --no-cov
```

Result: `46 passed in 7.70s`

```text
make docs-check
```

Result: release evidence hygiene passed and MkDocs built successfully.

```text
make check
```

Result: Ruff format/check clean, mypy clean for 211 source files, and backend
tests passed with `938 passed, 4 skipped in 47.18s`. Coverage remained above the
required 90% threshold at `90.86%`.

## Evidence Hygiene

The evidence above contains no secrets, tokens, cookies, customer data, or
private filesystem paths. The artifact is archived under `archive/vpw-evidence`
because `docs/evidence` is reserved for canonical report/evidence contract
artifacts.

## Residual Risk

None for same-batch duplicate dedup keys in the bulk import eligibility path.

## Scorecard Impact

Before: Backend/API retained a same-batch duplicate dedup-key gap that could
abort large imports through a unique-constraint failure.

After: Large imports with same-batch duplicate dedup keys avoid the unsafe bulk
insert path and use the existing dedupe-safe persistence flow.

Decision: This issue is ready for PR review after the evidence file, code,
tests, and GitHub Project #9 fields are linked.
