# VPW-AUD-502 Release-Readiness Evidence Gate

Audit source: Codex full-codebase audit on 2026-05-07
VPW ID: VPW-AUD-502
Category: CI/Release
Disposition: gap pending PR merge

## Decision

VPW-AUD-502 requires final project scoring to use fresh evidence for the exact
commit, tag, or release candidate being accepted. Historical PP artifacts,
ignored local build outputs, and previous candidate logs are not sufficient for
VPW-AUD-999 closure.

This evidence note records the release-readiness gate added to the public
production ledger and release operations docs. It is not a final project-wide
10/10 claim; that remains gated by VPW-AUD-999 after all category scorecards
are closed.

## Scope Changed

- `docs/public-production-release-evidence-ledger.md` now defines the
  VPW-AUD-999 fresh-evidence gate and lists the required command families.
- `docs/release_operations.md` now requires release-readiness evidence for the
  exact commit, tag, or release candidate before final scorecard acceptance.
- Evidence hygiene rules explicitly reject secrets, token values, cookies,
  customer exports, private absolute paths, and raw shell history.

## Validation

Commands run for this issue:

- `make docs-check` passed. Release-evidence hygiene reported stale wording
  audit OK, release ledger structure OK, and release evidence hygiene OK.
  MkDocs built successfully.
- `make check` passed with 970 tests passed, 4 skipped, and 90.96% coverage.
- `make dependency-audit` passed. Python `pip-audit` reported no known
  vulnerabilities, and frontend `npm audit --omit=dev` reported 0
  vulnerabilities.
- `make playwright-check` passed with 15 browser tests passed across desktop,
  mobile, responsive shell, findings-table scroll containment, and accessibility
  smoke coverage.
- `make release-readiness-check` passed. It covered the release gate, package
  build and twine validation, frontend lint/build/unit checks, generated client
  generation, dependency audit, Docker demo smoke, pipx/source smoke, demo
  evidence-bundle verification, Playwright, and production-like Docker smoke.
  This full gate was rerun after rebasing onto `origin/main` with
  VPW-AUD-501/#455 included, so the stricter generated-client drift check is in
  the final branch-head evidence.
- `git diff --exit-code -- frontend/src/client` passed after client generation.
- `git diff --check` passed before the PR commit.

## Required Final Evidence For VPW-AUD-999

VPW-AUD-999 can close only after fresh evidence exists for:

- `make check`
- frontend lint, build, and unit tests
- `make playwright-check`
- `make docs-check`
- `make dependency-audit`
- `make docker-demo-smoke`
- `make docker-production-smoke`
- `make api-client-drift-check`
- `make package-check`
- `make release-readiness-check`
- final residual-risk decisions

## Residual Risk

No CI/release documentation gap remains for requiring fresh evidence before the
final scorecard. The remaining risk is operational: VPW-AUD-999 must still link
the fresh command output or CI artifacts for the exact final candidate, and it
must not reuse this issue's local evidence as a substitute for final acceptance.

## Scorecard Impact

Before: final release-readiness acceptance could be misread as reusable from
historical PP evidence or local ignored artifacts.

After: final scoring is fail-closed on fresh evidence for the exact candidate,
with required categories and command families named explicitly.
