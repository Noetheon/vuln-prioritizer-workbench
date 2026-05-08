# VPW-AUD-601 Ignored Artifact Policy Evidence

Issue: VPW-AUD-601
Category: Repo Hygiene
Date: 2026-05-08

## Inventory Summary

`git status --short --ignored` was used to classify ignored local artifacts. The
raw local inventory was not committed because ignored files can contain private
paths, local environment data, tokens, cookies, or customer data.

Observed ignored categories:

- OS/editor metadata such as `.DS_Store`, IDE state, and agent-local notes.
- Dependency/runtime caches such as `.cache`, `.ruff_cache`, `.pytest_cache`,
  `.mypy_cache`, Playwright caches, and `node_modules`.
- Python bytecode and package metadata such as `__pycache__` and egg-info
  directories.
- Build, coverage, package, docs, and browser-test output such as `build`,
  `dist`, `site`, `htmlcov`, and `test-results`.
- Local runtime state such as logs, local SQLite databases, and upload scratch
  directories.

## Policy Decision

Ignored artifacts are local maintainer state and are not release evidence.
Release, scorecard, or public-production evidence must be tracked in a reviewed
repo path, linked from an issue or PR, and redacted so it contains no secrets,
tokens, cookies, customer data, or private absolute paths.

## Cleanup Guidance

- Use `make clean-local` for disposable command output, caches, logs, test
  output, build output, and local report artifacts.
- Use `make clean-deps` only when dependency directories and browser runtimes
  should also be removed.
- Do not delete user-local ignored artifacts as part of audit remediation unless
  the user explicitly approves that cleanup.
