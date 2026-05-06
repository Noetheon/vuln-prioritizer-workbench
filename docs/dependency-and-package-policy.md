# Dependency and Package Policy

This page defines the current dependency, lockfile, and Python package boundary
for release and security hygiene work.

## Backend Package Boundary

The `vuln-prioritizer` backend distribution intentionally ships both:

- the CLI/core package under `backend/src/vuln_prioritizer/**`
- the active Workbench FastAPI runtime under `backend/app/**`

This is the selected package story for the current tree. The package is not
CLI-only, and README/release wording should not imply that `app/*` is an
accidental inclusion.

The package boundary is enforced by:

- `backend/pyproject.toml`, where `tool.setuptools.packages.find.include`
  includes both `vuln_prioritizer*` and `app*`
- `make package-check`, which builds the backend distributions, validates their
  content with `scripts/check_package_contents.py`, and runs `twine check`
- `build/package-contents.json`, generated locally by the package-content check

The sdist and wheel must contain `app/main.py`, `app/api/main.py`, and
`vuln_prioritizer` CLI entrypoints. They must not include the backend test tree.

## Python Dependencies

Python dependency metadata is owned by `backend/pyproject.toml`. Direct runtime
requirements use bounded ranges so the package can receive compatible security
updates without a source release for every transitive patch.

`backend/requirements.txt` is the audited backend dependency input for the
repository release gate. It includes runtime and maintainer gate tools needed by
`make dependency-audit`, `make docs-check`, `make package-check`, and the local
workflow gate.

Current audit command:

```bash
python3 -m pip_audit --requirement backend/requirements.txt
```

The repository does not currently publish a separate fully pinned Python
production lockfile. Release evidence must state this explicitly if a release
owner requires byte-for-byte environment reproduction beyond the package
artifacts and checked-in dependency bounds.

## Frontend Dependencies

`frontend/package-lock.json` is the frontend source of truth for reproducible
npm installs. CI, Docker, local frontend gates, and dependency audit use npm
against that lockfile:

```bash
cd frontend && npm ci --workspaces=false
cd frontend && npm --workspaces=false audit --omit=dev
```

The root `bun.lock` is intentional because the root workspace keeps
Bun-compatible convenience scripts in `package.json`. It is not the audited
frontend install source. Do not use Bun lock updates as release evidence unless
a future issue changes the frontend package-manager policy.

## Dependabot Labels

Dependabot PR labels must use labels that exist in the repository taxonomy.
The current automation label policy is:

| Ecosystem | Labels |
| --- | --- |
| Python backend | `maintenance`, `dependencies`, `python` |
| GitHub Actions | `maintenance`, `dependencies`, `github-actions` |
| Frontend npm | `maintenance`, `dependencies`, `type:frontend`, `area:ui` |

Dependabot PR
[#287](https://github.com/Noetheon/vuln-prioritizer-workbench/pull/287)
remains the linked GitHub Actions dependency-update follow-up for this policy.
It should be merged, closed, or explicitly carried forward by a maintainer after
the release gate confirms the `actions/upload-artifact` upgrade is compatible
with the current artifact upload usage.

## Release Evidence Commands

Use these commands when dependency or package policy changes:

```bash
make dependency-audit
make package-check
make pipx-source-smoke
cd frontend && npm ci --workspaces=false && npm audit --omit=dev
```

Evidence must not include secrets, token values, cookies, customer exports,
private absolute paths, or shell history.
