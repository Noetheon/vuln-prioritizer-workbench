# CI cost optimization

This repository keeps required GitHub checks present on pull requests and skips
expensive work inside jobs when the change scope does not need it. Avoid
workflow-level path filters for required checks because a filtered workflow can
leave branch protection waiting for a check that never starts.

## Pull request checks

Ready pull requests keep the merge-safety checks that are required on `main`:

- `check (3.13)` runs the local-equivalent Python workflow gate on the current
  Docker runtime Python line.
- `check (3.11)` and `check (3.12)` keep the supported Python compatibility
  contexts visible.
- `frontend` runs frontend lint, build, generated-client drift, unit coverage,
  and the full Playwright suite unless the PR is documentation/archive-only or
  otherwise outside frontend/API/runtime scope.
- `compose-smoke` runs as a required Docker workflow job. For runtime-impacting
  Docker inputs, it runs both the demo and production-like Compose smokes; for
  unrelated paths, it exits with a clear skip message.
- `Analyze Python` CodeQL remains enabled on ready PRs because it is a required
  branch-protection context.

## Main checks

Pushes to `main` run the full merge validation:

- Python workflow gate on 3.11, 3.12, and 3.13.
- Full frontend Playwright suite.
- Demo and production-like Docker compose smokes, including the Compose
  Postgres Alembic/schema/repository check inside the backend container.
- CodeQL analysis.

## Manual checks

`workflow_dispatch` remains the full validation escape hatch:

- CI runs the full Python matrix and full frontend Playwright suite.
- Docker runs both Compose smokes regardless of changed paths.
- CodeQL can be started manually.

## Draft pull requests

Draft PRs keep lightweight successful required contexts where possible and skip
expensive work:

- Python matrix jobs exit after skip messages.
- Frontend exits after the scope decision.
- Docker Compose is skipped.
- CodeQL is skipped until the PR is ready.

When the PR is marked ready, normal ready-PR checks run.

The required PR workflows explicitly listen for the `ready_for_review` activity.
That makes GitHub start a fresh ready-state check run when a draft PR becomes
ready. Rerunning an older draft workflow is not equivalent because GitHub
reuses the original draft event payload for that rerun.

## Documentation and archive changes

Documentation, archive, Markdown-only, and workflow-only PRs keep required check
contexts visible but avoid frontend browser work and Docker Compose. The Python
workflow gate still runs on the primary PR Python version so docs hygiene,
actionlint, packaging guardrails, and pre-commit checks remain covered.

## Frontend-only changes

Frontend route, component, and CSS changes run the frontend job with lint, build,
generated-client drift, unit coverage, and the full Playwright suite. They do
not run Docker Compose unless Docker build inputs such as frontend package files,
Dockerfiles, nginx config, or build config changed.

## Backend and runtime-impacting changes

Backend, compose, Dockerfile, dependency, runtime script, frontend package, and
frontend build-config changes run both Docker Compose smokes. This keeps
runtime/deployment coverage for changes that can alter container startup, image
contents, backend API behavior, frontend image construction, same-origin
routing, public-deployment controls, or report download paths.

## Tradeoffs

The main tradeoff is that dependency and runtime PRs pay for the full supported
Python matrix. That cost is intentional for compatibility-sensitive changes,
while frontend and Docker jobs still skip internally when scope analysis shows
they are not affected. Ready PRs that touch frontend/API/runtime behavior also
run the full browser suite before merge.

CodeQL stays conservative on ready PRs because branch protection currently
requires `Analyze Python`. If branch protection changes later, CodeQL can move
to `main`, schedule, and manual-only runs for additional savings.
