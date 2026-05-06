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
They also must not reintroduce removed legacy Workbench runtime packages under
`vuln_prioritizer/api`, `vuln_prioritizer/db`, or `vuln_prioritizer/web`.

## Coverage Boundary

The current backend pytest coverage gate in `backend/pyproject.toml` measures
`vuln_prioritizer` and keeps the CLI/core package at the release threshold. The
Workbench app under `backend/app` is intentionally shipped in the same
distribution and is tested by the API suites, but it is not yet included in the
same coverage measurement.

Recommended follow-up, owned by the coverage-config maintainer: either add
`--cov=app` to the enforced backend coverage command with an agreed threshold,
or document and enforce a separate Workbench app coverage gate. Do not treat
package inclusion of `app*` as coverage proof by itself.

## Python Dependencies

Python dependency metadata is owned by `backend/pyproject.toml`. Direct runtime
requirements use bounded ranges so the package can receive compatible security
updates without a source release for every transitive patch.

`backend/requirements.txt` is the authoritative Python audit input for the
repository release gate. It is intentionally a bounded audit input, not a
production environment freeze: every direct runtime dependency and every
`[project.optional-dependencies].dev` maintainer dependency from
`backend/pyproject.toml` must appear there with the same bounded policy shape.
Package metadata remains bounded so compatible security updates can still land
without a source release for every transitive patch.

Regenerate or refresh the audit input by reconciling the union of
`project.dependencies` and `project.optional-dependencies.dev` from
`backend/pyproject.toml` into `backend/requirements.txt`, preserving bounded
ranges rather than hard pins unless a future issue explicitly chooses a frozen
lockfile. The drift check is enforced by:

```bash
python3 scripts/check_release_evidence_hygiene.py
```

Current audit command:

```bash
make dependency-audit
```

`make dependency-audit` first runs the drift check above, then audits
`backend/requirements.txt` with `pip-audit`, and finally audits
`frontend/package-lock.json` through npm. The repository does not currently
publish a separate fully pinned Python production lockfile. Release evidence
must state this explicitly if a release owner requires byte-for-byte environment
reproduction beyond the package artifacts and checked-in dependency bounds.

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
