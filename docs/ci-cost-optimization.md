# CI cost optimization

This repository keeps required GitHub checks present on pull requests and skips
expensive work inside jobs when the change scope does not need it. Avoid
workflow-level path filters for required checks because a filtered workflow can
leave branch protection waiting for a check that never starts.

## Pull request checks

Ready pull requests keep the merge-safety checks that are required on `main`:

- `check (3.12)` runs the local-equivalent Python workflow gate.
- `check (3.11)` remains as a required context and exits with a clear skip
  message on pull requests. The full 3.11 gate runs on `main` and manual
  dispatch.
- `frontend` runs frontend lint, build, generated-client drift, and Playwright
  smoke unless the PR is documentation, archive, or workflow-only.
- `compose-smoke` runs as a required Docker workflow job, but skips Compose when
  no runtime-impacting Docker inputs changed.
- `Analyze Python` CodeQL remains enabled on ready PRs because it is a required
  branch-protection context.

## Main checks

Pushes to `main` run the full merge validation:

- Python workflow gate on 3.11 and 3.12.
- Full frontend Playwright suite.
- Docker compose smoke.
- CodeQL analysis.

## Manual checks

`workflow_dispatch` remains the full validation escape hatch:

- CI runs the full Python matrix and full frontend Playwright suite.
- Docker runs Compose regardless of changed paths.
- CodeQL can be started manually.

## Draft pull requests

Draft PRs keep lightweight successful required contexts where possible and skip
expensive work:

- Python matrix jobs exit after skip messages.
- Frontend exits after the scope decision.
- Docker Compose is skipped.
- CodeQL is skipped until the PR is ready.

When the PR is marked ready, normal ready-PR checks run.

## Documentation and archive changes

Documentation, archive, Markdown-only, and workflow-only PRs keep required check
contexts visible but avoid frontend browser work and Docker Compose. The Python
workflow gate still runs on the primary PR Python version so docs hygiene,
actionlint, packaging guardrails, and pre-commit checks remain covered.

## Frontend-only changes

Frontend route, component, and CSS changes run the frontend job with lint, build,
generated-client drift, and Playwright smoke. They do not run Docker Compose
unless Docker build inputs such as frontend package files, Dockerfiles, nginx
config, or build config changed.

## Backend and runtime-impacting changes

Backend, compose, Dockerfile, dependency, runtime script, frontend package, and
frontend build-config changes run Docker Compose. This keeps runtime/deployment
coverage for changes that can alter container startup, image contents, backend
API behavior, or frontend image construction.

## Tradeoffs

The main tradeoff is that pull requests no longer run the expensive Python gate
on every supported Python version. The 3.11 required context remains present,
but the full 3.11 gate runs after merge on `main` and can be run manually before
merge when a dependency or compatibility-sensitive change warrants it.

CodeQL stays conservative on ready PRs because branch protection currently
requires `Analyze Python`. If branch protection changes later, CodeQL can move
to `main`, schedule, and manual-only runs for additional savings.
