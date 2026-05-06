# Repository Archive

This directory holds historical planning and evidence artifacts that are useful
for audit, release reconstruction, or handoff, but are no longer part of the
public MkDocs documentation surface.

- `vpw-evidence/`: historical VPW evidence markdown, screenshots, JSON exports,
  and demo bundles.
- `historical-planning/`: superseded Workbench planning documents and early API
  skeleton notes.

Current user and maintainer documentation lives in `docs/`, `README.md`, and the
repository-root operational files.

## Artifact Boundaries

- `build/`: ignored local command output, generated parity reports, package
  inspection JSON, release scratch files, and temporary evidence generated while
  validating a change.
- `docs/evidence/`: small, reviewed, contract-level evidence artifacts that are
  referenced by schemas or regression tests. Screenshots and broad demo evidence
  should not be added here by default.
- `archive/vpw-evidence/`: historical release, demo, screenshot, and bundle
  evidence kept out of the public docs build surface.
- local ignored paths such as `.cache/`, `.pytest_cache/`, `.ruff_cache/`,
  `dist/`, `site/`, `htmlcov/`, and `test-results/`: disposable maintainer
  outputs cleaned by `make clean-local`.
