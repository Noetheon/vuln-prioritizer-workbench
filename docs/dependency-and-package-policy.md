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
  content with `scripts/check_package_contents.py`, runs `twine check`, installs
  the built wheel into a temporary virtualenv, imports `app.main:create_app`, and
  migrates a temporary Workbench database through Alembic head
- `build/package-contents.json`, generated locally by the package-content check

The sdist and wheel must contain `app/main.py`, `app/api/main.py`, and
`vuln_prioritizer` CLI entrypoints, plus the active Workbench Alembic migration
tree. They must not include the backend test tree. They also must not
reintroduce removed legacy Workbench runtime packages under
`vuln_prioritizer/api`, `vuln_prioritizer/db`, or `vuln_prioritizer/web`.

## Coverage Boundary

The current backend pytest coverage gate in `backend/pyproject.toml` measures
both `vuln_prioritizer` and the active FastAPI Workbench package under
`backend/app`. This keeps the CLI/core package and shipped API runtime inside the
same enforced release threshold.

Recommended follow-up, owned by the coverage-config maintainer: keep the
coverage command aligned with the package boundary when modules move. Do not
treat package inclusion of `app*` as coverage proof by itself.

## Python Dependencies

Python dependency metadata is owned by `backend/pyproject.toml`. Direct runtime
requirements use bounded ranges so the package can receive compatible security
updates without a source release for every transitive patch.

`backend/requirements.txt` is the authoritative bounded Python audit policy
input. It is intentionally not a production environment freeze: every direct
runtime dependency and every `[project.optional-dependencies].dev` maintainer
dependency from `backend/pyproject.toml` must appear there with the same bounded
policy shape. Package metadata remains bounded so compatible security updates
can still land without a source release for every transitive patch.

The reproducible Python resolution artifact is the root `uv.lock`. The release
dependency-audit input is `backend/requirements.lock.txt`, exported from
`uv.lock` with exact pins and hashes for runtime plus maintainer dependencies.
The backend Docker install input is the separate
`backend/requirements.runtime.lock.txt`, exported from the same `uv.lock` for
Python 3.12 without dev extras. Keep all three committed together when Python
dependency metadata changes. The backend Docker image installs the local backend
package from `backend/pyproject.toml` with `--no-deps` after installing the
runtime lock, so runtime containers do not carry test, docs, or maintainer
tooling. `backend/requirements.lock.txt` remains the audited candidate
dependency set for release evidence.

Regenerate or refresh the audit input by reconciling the union of
`project.dependencies` and `project.optional-dependencies.dev` from
`backend/pyproject.toml` into `backend/requirements.txt`, preserving bounded
ranges rather than hard pins. Then refresh the lock artifacts:

```bash
uv lock --python 3.11
uv export --format requirements.txt --all-packages --all-extras \
  --no-emit-project --no-emit-workspace --locked \
  --python 3.11 --output-file backend/requirements.lock.txt --no-progress
uv export --format requirements.txt --package vuln-prioritizer --no-dev \
  --no-emit-project --no-emit-workspace --locked \
  --python 3.12 --output-file backend/requirements.runtime.lock.txt --no-progress
```

The drift and lock checks are enforced by:

```bash
make python-lock-check
```

Current audit command:

```bash
make dependency-audit
```

`make dependency-audit` first runs the drift and lock checks above, including
the Docker runtime lock check, then audits `backend/requirements.lock.txt` with
`pip-audit`, and finally audits `frontend/package-lock.json` through npm.
Release evidence must refresh and record these exact lock artifacts for the
candidate being handed off.

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

## Container Images

The checked-in Dockerfiles use named upstream image tags so maintainers can
receive compatible base-image security updates during local-first development.
That is not byte-for-byte production pinning. Release owners who need pinned
container provenance must record the resolved image digests for the backend,
frontend, and compose stack used by the release candidate.

The Docker workflow smoke-tests the built Workbench stack, emits SBOMs for the
backend and frontend images, and fails CI on fixable critical image
vulnerabilities. Public production release evidence still needs
candidate-specific image digests and any required signing/provenance attestation
for those exact images.

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
