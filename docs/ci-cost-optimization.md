# CI Cost Optimization

This repository keeps PR safety checks active while reducing duplicate and
long-running GitHub Actions work.

## Pull Requests

Pull requests to `main` run:

- `CI / check` for the Python workflow gate on the supported Python matrix.
- `CI / action-smoke` for the local GitHub Action smoke path.
- `CI / frontend` for frontend lint, build, generated-client drift, and the
  Playwright smoke spec.
- `Docker / compose-smoke` for runtime-impacting changes.
- `CodeQL / Analyze Python` for security analysis.

Docs/evidence-only PRs still run a Docker workflow check, but the expensive
Docker compose build is skipped after the workflow confirms that only
documentation/evidence paths changed. This keeps the check from staying pending
while avoiding container build minutes for non-runtime changes.

## Pushes To Main

Pushes to `main` run the post-merge version of the same CI workflows. The
frontend job runs the full Playwright suite on `main`, while PRs run the smoke
spec for faster feedback.

## Manual Validation

Use `workflow_dispatch` for manual full validation:

- `CI` runs the Python gate, action smoke, frontend build/lint/client drift, and
  full Playwright suite.
- `Docker` runs the compose smoke check.
- `Maintenance`, `Release`, and `TestPyPI Publish` remain manually runnable for
  release and packaging validation.

## Nightly Or Scheduled Validation

Scheduled jobs remain limited to:

- weekly CodeQL security analysis
- weekly Maintenance release-check and install-smoke dry runs

No new scheduled workflow was added.

## Moved Out Of Every-Commit Execution

- Feature-branch `push` events no longer run duplicate `CI` and `Docker`
  workflows when a PR already runs the same validation.
- Full Playwright no longer runs on every PR commit; PRs use the smoke spec,
  while full Playwright runs on `main` and manual CI runs.
- Playwright evidence is uploaded only on failure.

## Artifact And Cache Policy

- Failure/debug artifacts use short retention windows of three days.
- Release/TestPyPI build artifacts use three-day retention because downstream
  jobs in the same workflow consume them.
- Existing `setup-python` pip caching remains in place.

## Expected Cost Reduction

The main savings come from:

- cancelling stale runs after new pushes
- avoiding duplicate feature-branch push workflows
- replacing PR full Playwright with the smoke spec
- skipping Docker compose for docs/evidence-only PRs
- limiting artifact uploads and retention

## Risks And Tradeoffs

- Full Playwright regressions may be found after merge instead of during every
  PR. The PR smoke suite still covers core route rendering.
- Docker compose is skipped for docs/evidence-only changes based on changed file
  paths. Runtime-impacting files still run Docker.
- Required checks should not remain pending because workflows still run; expensive
  steps are skipped inside jobs rather than by workflow path filters.
