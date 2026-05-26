# Repository Archive

This directory holds historical planning and evidence artifacts that are useful
for audit, release reconstruction, or handoff, but are no longer part of the
public MkDocs documentation surface.

- `vpw-evidence/`: minimal historical VPW evidence entrypoints, selected
  Markdown notes, and the small evidence bundle still referenced by contract
  evidence.
- `historical-planning/`: a pointer for superseded planning material. Full
  planning drafts are intentionally not retained in the trimmed archive.

Current user and maintainer documentation lives in `docs/`, `README.md`, and the
repository-root operational files.

Use `docs/documentation-evidence-matrix.md` before promoting an archived claim
back into active docs. Archive files can support history or demo reconstruction,
but they do not override current code, tests, release gates, or primary-source
provider facts.

## Artifact Boundaries

- `build/`: ignored local command output, generated parity reports, package
  inspection JSON, release scratch files, and temporary evidence generated while
  validating a change.
- `docs/evidence/`: small, reviewed, contract-level evidence artifacts that are
  referenced by schemas or regression tests. Screenshots and broad demo evidence
  should not be added here by default.
- `archive/vpw-evidence/`: minimal historical release/demo entrypoints and the
  retained bundle artifact kept out of the public docs build surface.
- local ignored paths such as `.cache/`, `.pytest_cache/`, `.ruff_cache/`,
  `dist/`, `site/`, `htmlcov/`, and `test-results/`: disposable maintainer
  outputs cleaned by `make clean-local`.

## Ignored Local Artifact Policy

Ignored files are local maintainer state, not release evidence. They can be
useful while validating a change, but they are not reviewed, shipped, or used to
support public-production readiness claims unless a reviewer promotes a redacted
summary into a tracked evidence file.

Use `git status --short --ignored` before release or scorecard handoff:

```bash
git status --short --ignored
```

Expected ignored categories include editor metadata, dependency caches, Python
bytecode caches, coverage output, package/build output, Playwright or test
results, local logs, local databases, and local upload/report scratch data.
Review new categories before relying on them in evidence, especially files that
could contain secrets, tokens, cookies, customer data, or private paths.

Use `make clean-local` to remove disposable command output, caches, logs, and
test/build products. Use `make clean-deps` only when dependency directories and
browser runtimes should also be removed. Do not delete user-local artifacts as
part of an audit issue without explicit approval.
