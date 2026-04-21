# Consumer Workflow Examples

These workflows are consumer-side examples for the current GitHub Action and CLI surface.

They are intentionally stored under `.github/examples/` instead of `.github/workflows/` so that the repository documents supported integration patterns without automatically running them inside this repo.

Pin the action to a release tag in consumer repositories. The examples use `@v1.1.0` rather than `@main` for that reason.

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

- Consumers should pin the action to a release tag once one is available for the desired version.
- `actions/checkout` is still required in the consuming workflow because the scanned files live in the consumer repository, not in the action repository.
- The action installs `vuln-prioritizer` from the action checkout and runs the local CLI entrypoint.
