# Contributing

Thanks for contributing to `vuln-prioritizer`.

## Scope Guardrails

- This project prioritizes known CVEs. It is not a vulnerability scanner.
- Prefer official/public sources only: NVD, FIRST EPSS, CISA KEV.
- Do not add heuristic or LLM-generated CVE-to-ATT&CK mappings.
- Keep ATT&CK optional and offline-file-based unless the project scope changes explicitly.

## Local Development

```bash
python3 -m venv .venv
source .venv/bin/activate
make install
```

## Local Quality Gate

GitHub Actions are intentionally not required for day-to-day development. The CI workflow mirrors the local gate below, so run all checks locally before pushing:

```bash
make check
```

This runs:

- `ruff format --check`
- `ruff check`
- `mypy src`
- `pytest`

## Local Workflow Equivalent

When hosted GitHub Actions are unavailable, the recommended local equivalent is:

```bash
make workflow-check
```

This adds:

- `python3 -m pre_commit run --all-files`
- `python3 -m mkdocs build --clean`
- `python3 -m build`
- `python3 -m twine check dist/*`

## Demo Artifacts

When output changes materially, regenerate the checked-in demo artifacts:

```bash
make demo-report
make demo-compare
make demo-explain
```

For a full release-oriented local sweep:

```bash
make release-check
```

`make release-check` remains the stricter maintainer sweep because it also regenerates the checked-in demo artifacts before packaging.

To validate only the generated distribution artifacts and package metadata:

```bash
make package-check
```

To validate the browsable documentation site:

```bash
make docs-check
```

## Commit Discipline

- Keep commits focused.
- Update tests with behavioral changes.
- Update `CHANGELOG.md` for user-visible or maintainer-relevant changes when appropriate.
- Do not commit local secrets or local handoff notes.
- Prefer deterministic mocks in tests over live network calls.
