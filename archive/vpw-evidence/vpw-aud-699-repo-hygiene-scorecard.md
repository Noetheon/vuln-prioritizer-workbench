# VPW-AUD-699 Repo Hygiene 10/10 Scorecard

Issue: VPW-AUD-699
Category: Repo Hygiene
Date: 2026-05-08

## Decision

Repo Hygiene is rated 10/10 after PP13 child remediation closes.

Final project-wide 10/10 remains gated by VPW-AUD-999.

## Child Evidence

| Issue | PR | Decision | Evidence |
| --- | --- | --- | --- |
| VPW-AUD-601 / #426 | #459 | Ignored local artifacts are documented as local maintainer state, not release evidence. | `archive/vpw-evidence/vpw-aud-601-ignored-artifact-policy.md` |
| VPW-AUD-602 / #427 | #460 | Evidence ownership boundaries are explicit for `docs/evidence`, archive evidence, CI artifacts, and screenshots. | `archive/vpw-evidence/vpw-aud-602-archive-evidence-boundary.md` |
| VPW-AUD-603 / #428 | #461 | Active runtime naming is Workbench-branded; template-era names are retained only as documented compatibility or historical/test/contract references. | `archive/vpw-evidence/vpw-aud-603-template-runtime-naming.md` |

## Fresh Validation Targets

Required VPW-AUD-699 validation:

- `git status --short --branch`
- `git status --short --ignored`
- `make docs-check`

The raw ignored inventory is not committed because ignored files can include
private paths, local secrets, cookies, customer data, or local runtime state.
The category scorecard records only sanitized inventory classes.

## Ignored Inventory Classes

Expected ignored local classes observed during PP13:

- OS/editor metadata and local agent state.
- Python, pytest, mypy, Ruff, Playwright, and package caches.
- Dependency directories and generated frontend/backend build output.
- Coverage, docs-build, package, and browser-test output.
- Local logs, local SQLite databases, upload scratch data, and report scratch
  data.

## Residual Risk

No repo hygiene blocker remains for PP13. Local ignored artifacts still exist by
design and are governed by the ignored artifact policy. Historical evidence is
retained intentionally and governed by the archive/evidence ownership matrix.
Template-era names remain only where they are compatibility aliases, historical
references, tests, example artifact names, decision-template contract fields, or
CSS properties.

## Score

Before PP13: 7/10.

After PP13: 10/10.

Decision: repo hygiene can close at 10/10 once this scorecard PR is merged and
Project #9 is synchronized.
