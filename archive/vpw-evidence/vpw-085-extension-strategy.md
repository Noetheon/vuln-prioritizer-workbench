# VPW-085 Extension Strategy Evidence

## Scope

VPW-085 documents the parser and provider extension strategy for future
maintainer-reviewed contributions:

- Parser contract for template Workbench importers and CLI input parser
  definitions.
- Provider contract for static local provider definitions and enrichment
  adapters.
- Fixture requirements for positive, negative, degraded, and offline provider
  cases.
- Contribution checklist with docs, tests, support matrix, generated client, and
  schema expectations.
- Explicit safety boundaries against runtime plugin discovery, remote code
  loading, scanner execution, arbitrary provider endpoint overrides, and
  live-network-only required CI.

## Evidence Paths

- Contributor doc: `docs/extension_strategy.md`
- CONTRIBUTING link: `CONTRIBUTING.md`
- Roadmap link: `docs/roadmap.md`
- Support matrix link: `docs/support_matrix.md`
- MkDocs nav: `mkdocs.yml`
- Example stub: `docs/examples/extension_stub.py`
- Stub test: `backend/tests/test_extension_sdk.py`

## Validation Evidence

| Gate | Evidence |
| --- | --- |
| Extension stub and SDK contract tests | `python3 -m pytest -q backend/tests/test_extension_sdk.py --no-cov` passed: 5 passed. |
| Example stub compile check | `python3 -m py_compile docs/examples/extension_stub.py` passed. |
| Example stub lint/format | `python3 -m ruff check docs/examples/extension_stub.py backend/tests/test_extension_sdk.py && python3 -m ruff format --check docs/examples/extension_stub.py backend/tests/test_extension_sdk.py` passed. |
| Documentation build | `make docs-check` passed. |
| Full backend quality gate | `make check` passed: ruff format, ruff check, mypy, 892 passed, 7 skipped, 90.77% coverage. |
| Whitespace guard | `git diff --check` passed. |

## Residual Risk

This strategy intentionally does not add runtime plugin loading. Future parser or
provider contributions still require normal PR review, fixtures, tests, and
security review before being registered in the application.
