# Consumer Workflow Examples

These workflows are consumer-side examples for the current GitHub Action and CLI surface.

They are intentionally stored under `.github/examples/` instead of `.github/workflows/` so that the repository documents supported integration patterns without automatically running them inside this repo.

Pin the action to a release tag or commit SHA in consumer repositories. The examples use the placeholder `@vX.Y.Z` so they stay aligned with the current `main` branch docs instead of going stale when the latest public tag lags behind `main`.

## Included Examples

- [code-scanning-sarif.yml](./code-scanning-sarif.yml)
- [pr-comment-report.yml](./pr-comment-report.yml)
- [html-report-artifact.yml](./html-report-artifact.yml)

## Current Contracts

The action and examples assume the current repository provides:

- scanner-native JSON input support for `analyze`
- `analyze --format sarif`
- deterministic `--fail-on` exit codes
- `report html --input analysis.json --output report.html`
- a composite GitHub Action at repository root (`action.yml`)

## Integration Notes

- Consumers should replace `@vX.Y.Z` with the release tag or commit SHA that matches the surface they want to consume.
- `actions/checkout` is still required in the consuming workflow because the scanned files live in the consumer repository, not in the action repository.
- The action installs `vuln-prioritizer` from the action checkout and runs the local CLI entrypoint.
