# CI cost optimization

This repository keeps required GitHub checks present on pull requests and skips
expensive work inside jobs when the change scope does not need it. Avoid
workflow-level path filters for required checks because a filtered workflow can
leave branch protection waiting for a check that never starts.

## Pull request checks

Ready pull requests keep the merge-safety checks that are required on `main`:

- `check (3.11)` runs the local-equivalent Python workflow gate.
- `check (3.12)` and `check (3.13)` run backend compatibility tests without
  duplicating coverage, static analysis, packaging, or docs gates.
- Docs-only PRs keep the required Python check contexts visible, but only
  `check (3.11)` installs the docs toolchain and runs `make docs-check`;
  compatibility legs exit with scoped skip messages.
- `frontend` runs frontend lint, build, generated-client drift, unit coverage,
  and scoped Playwright coverage unless the PR is documentation/archive-only or
  otherwise outside frontend/API/runtime scope. Frontend static/unit checks can
  run without browser installation for non-browser-impacting backend changes.
  API/runtime or route changes use Chromium and mobile Chromium; UI, style,
  browser-config, `main`, and manual runs keep the full browser and
  visual-regression path.
- `compose-smoke` runs as a required Docker workflow job. For runtime-impacting
  Docker inputs, it runs the demo Compose smoke. Production-like Compose and
  image security scans run for production, container, dependency, security, CI,
  `main`, and manual inputs; unrelated paths exit with a clear skip message.
- `Analyze Python` CodeQL remains a visible required branch-protection context,
  but docs-only/non-source PRs skip the CodeQL initialization and analysis steps
  inside the job.

## Main checks

Pushes to `main` run the full merge validation:

- Full Python workflow gate on 3.11 plus backend compatibility tests on 3.12
  and 3.13.
- Full frontend Playwright suite and visual-regression baseline.
- Demo and production-like Docker compose smokes plus image security scans,
  including the Compose Postgres Alembic/schema/repository check inside the
  backend container.
- CodeQL analysis.
- The weekly `CI Cost Report` workflow samples recent successful CI, Docker,
  and CodeQL runs and writes average, median, and p95 job-minutes to the run
  summary and artifact.

## Manual checks

`workflow_dispatch` remains the full validation escape hatch:

- CI runs the full Python workflow gate on 3.11, compatibility tests on 3.12
  and 3.13, and the full frontend Playwright/visual-regression gate.
- Docker runs both Compose smokes and image security scans regardless of
  changed paths.
- CodeQL can be started manually.
- `CI Cost Report` can be started manually after workflow changes to compare
  real post-change runner minutes with the historical baseline.

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
contexts visible but avoid frontend browser work, Docker Compose, and CodeQL
analysis unless source/security-relevant files changed. The Python workflow gate
still runs docs hygiene on the primary PR Python version; backend compatibility
legs skip because Python runtime compatibility is not exercised by docs-only
changes.

## Frontend-only changes

Frontend route, component, and CSS changes run the frontend job with lint, build,
generated-client drift, unit coverage, full browser coverage, and the visual
regression baseline. Frontend route and Playwright spec changes run browser
coverage without necessarily triggering the visual baseline. Backend/API-only
changes that still need frontend validation run the same static/unit/client
checks with Chromium and mobile Chromium instead of installing every browser
engine. Backend changes outside API/browser runtime scope keep the static,
generated-client, and unit gates but skip Playwright. Frontend
route/component/CSS changes do not run Docker Compose unless Docker build inputs
such as frontend package files, Dockerfiles, nginx config, or build config
changed.

## Backend and runtime-impacting changes

Backend, dependency, runtime script, frontend package, and frontend build-config
changes run at least the Docker demo smoke. Compose, Dockerfile, nginx,
production-smoke, runtime config, Makefile, and Docker workflow changes run the
full demo plus production-like Compose path. Dockerfile, dependency, Compose,
Grype, and Docker workflow changes also run image SBOM and vulnerability scans.
This keeps runtime/deployment coverage for changes that can alter container
startup, image contents, backend API behavior, frontend image construction,
same-origin routing, public-deployment controls, or report download paths.
The Docker workflow also runs weekly in full mode to catch new fixable
high/critical image vulnerabilities that appear after a PR has already merged.

## Tradeoffs

The main tradeoff is that compatibility-sensitive changes still pay for multiple
Python runtimes and Docker-relevant changes still build containers before merge.
The 3.12/3.13 legs now run a high-signal runtime/parser/API compatibility
subset, not a second and third copy of the full docs/static/coverage gate.
Frontend/API PRs use representative browser coverage unless the changed paths
can affect UI rendering, browser behavior, or visual baselines. Docker PRs run
the production-like smoke and image scans only when the changed paths can affect
production routing, image contents, or scan policy.

CodeQL keeps required check names on PRs, but source-scopes the expensive
analysis steps and relies on `main`, weekly schedule, and manual runs for full
repository security analysis outside PR source changes.

## Measuring impact

Use the local report after a workflow change or from a checked-out PR branch:

```bash
make ci-cost-report
```

The weekly `CI Cost Report` workflow runs the same script and uploads
`ci-cost-report.md` plus `ci-cost-report.json`. Treat those post-change
job-minute summaries as the authoritative cost baseline; local wall-clock test
times are useful for QA, but GitHub billed minutes come from Actions job
durations.
