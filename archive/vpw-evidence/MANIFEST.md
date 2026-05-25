# VPW Evidence Manifest

Historical evidence was moved from `docs/evidence/` into this archive during the
repo hygiene cleanup.

This manifest is a historical inventory. It does not certify current Workbench
behavior, current provider state, or public deployment readiness. Use
`docs/documentation-evidence-matrix.md` and current validation output before
using archived artifacts as support for active documentation.

## Directory Inventory

- `final-demo-flow/`: compact historical demo notes and ATT&CK mapping summary.
- `presentation-pack/`: compact presentation evidence index.
- Root-level `vpw-*.md`: selected issue-level evidence notes still referenced by
  active docs.
- `vpw-051-evidence-bundle.zip`: the retained historical evidence bundle needed
  by `docs/evidence/vpw-052-positive-verification.json`.
- `BINARY-MANIFEST.json`: hash-pinned inventory of tracked binary evidence,
  including purpose labels and ZIP-safety validation.

## Ownership Rules

- Do not add durable historical screenshots or broad visual proof sets unless a
  maintainer explicitly asks for them and accepts the repository-size cost.
- Keep VPW-AUD scorecards and other audit-remediation Markdown out of the
  repository unless a maintainer explicitly asks for a durable artifact.
- Keep `docs/evidence/` limited to contract fixtures that are referenced by
  schemas or regression tests.
- Keep raw CI logs, package files, Docker logs, and Playwright reports as CI
  artifacts for the exact run unless a redacted Markdown summary is needed in
  the repository.
- Update this manifest when adding a new evidence subdirectory or a new class of
  root-level artifact.
- Update `BINARY-MANIFEST.json` with
  `python3 scripts/check_archive_evidence_manifest.py --update` when adding,
  removing, or intentionally replacing tracked binary evidence, then run
  `python3 scripts/check_archive_evidence_manifest.py`.
- Do not archive secrets, tokens, cookies, customer data, private absolute
  paths, or raw local ignored-artifact inventories.

## Removed During Cleanup

- `vpw-011-openapi-docs.png` was deleted because it had no text references and
  was no longer used by tests, docs, or release evidence.
- Unreferenced archived Markdown notes and superseded planning drafts were
  deleted during the 2026-05-08 documentation hygiene cleanup. Retained
  Markdown files are either archive entrypoints, active demo/presentation
  summaries, or evidence notes still referenced by current docs/tests.
- The 2026-05-25 archive trim removed historical screenshots, design-system
  proof images, duplicate machine-readable exports, and the superseded
  Workbench masterplan from `main`. Current product truth now comes from active
  docs, tests, generated fixtures, and live validation output rather than large
  archived visual proof sets.
