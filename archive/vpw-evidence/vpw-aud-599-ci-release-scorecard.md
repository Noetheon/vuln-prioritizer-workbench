# VPW-AUD-599 CI/Release Category Scorecard

Audit source: Codex full-codebase audit on 2026-05-07
VPW ID: VPW-AUD-599
Category: CI/Release
Disposition: verified-shipped pending PR merge

## Decision

CI/Release is ready to score 10/10 after the PP12 child issues closed with
fresh pull requests, local validation, GitHub checks, and residual-risk
decisions. This is a category score only; final project-wide 10/10 and
public-production readiness remain gated by VPW-AUD-999.

## Child Issue Evidence

| VPW ID | Issue | PR | Result |
| --- | --- | --- | --- |
| VPW-AUD-501 | #423 | #455 | Closed. `make frontend-check` now fails closed on generated API client drift after generation. |
| VPW-AUD-502 | #424 | #457 | Closed. Final scorecard acceptance now requires fresh release-readiness evidence for the exact commit, tag, or release candidate. |

## Validation

Commands run for this scorecard:

- `make api-client-drift-check` passed. The generated client completed and
  `git diff --exit-code -- frontend/src/client` was clean.
- `make package-check` passed. Backend package build completed, package
  contents check was OK, and `twine check dist/*` passed for the sdist and
  wheel.
- `make dependency-audit` passed. Python `pip-audit` reported no known
  vulnerabilities, and frontend `npm audit --omit=dev` reported 0
  vulnerabilities.
- `make release-readiness-check` passed. It covered workflow/check gates,
  backend tests, package validation, frontend lint/build/unit, generated-client
  drift check, dependency audit, Docker demo smoke, pipx/source smoke, demo
  evidence-bundle verification, Playwright desktop/mobile/a11y smoke, and
  production-like Docker smoke.
- `gh issue view` for #423 and #424 confirmed both child issues are closed.
- `git diff --exit-code -- frontend/src/client` passed after the release
  readiness client generation.
- `git diff --check` passed before the PR commit.

## Residual Risk

No CI/Release-category residual risk remains from VPW-AUD-501 and
VPW-AUD-502. Final project-wide acceptance still requires VPW-AUD-699 and
VPW-AUD-999 evidence, and VPW-AUD-999 must link fresh final-candidate evidence
instead of reusing this category scorecard as release acceptance.

## Scorecard Impact

Before: 8/10. Local generated-client refresh could hide drift, and final
release-readiness acceptance could be misread as reusable from historical PP
evidence or ignored local artifacts.

After: 10/10 for the CI/Release category. Client drift is fail-closed, release
readiness requires fresh candidate evidence, and the category scorecard links
the current package, dependency, client, Playwright, Docker, and release gates.
