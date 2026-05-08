# VPW Evidence Manifest

Historical evidence was moved from `docs/evidence/` into this archive during the
repo hygiene cleanup.

## Directory Inventory

- `final-demo-flow/`: final demo screenshots and summary notes.
- `presentation-pack/`: presentation evidence index and proof-set pointers.
- `vpw-design-system-foundation/`: design-system screenshot and showcase set.
- Root-level `vpw-*.md`: selected issue-level evidence notes that are still
  referenced by active docs or tests.
- Root-level `vpw-*.png`: issue-level browser evidence.
- Root-level `vpw-*.json`, `vpw-*.csv`, and `vpw-*.zip`: machine-readable
  validation and bundle artifacts.

## Ownership Rules

- Keep durable historical screenshots and product evidence in this archive
  instead of `docs/evidence/`.
- Keep VPW-AUD scorecards and other audit-remediation Markdown out of the
  repository unless a maintainer explicitly asks for a durable artifact.
- Keep `docs/evidence/` limited to contract fixtures that are referenced by
  schemas or regression tests.
- Keep raw CI logs, package files, Docker logs, and Playwright reports as CI
  artifacts for the exact run unless a redacted Markdown summary is needed in
  the repository.
- Update this manifest when adding a new evidence subdirectory or a new class of
  root-level artifact.
- Do not archive secrets, tokens, cookies, customer data, private absolute
  paths, or raw local ignored-artifact inventories.

## Removed During Cleanup

- `vpw-011-openapi-docs.png` was deleted because it had no text references and
  was no longer used by tests, docs, or release evidence.
- Unreferenced archived Markdown notes and superseded planning drafts were
  deleted during the 2026-05-08 documentation hygiene cleanup. Retained
  Markdown files are either archive entrypoints, active demo/presentation
  summaries, or evidence notes still referenced by current docs/tests.
