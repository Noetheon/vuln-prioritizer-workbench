# Dependency and Package Policy

This page defines the current dependency, lockfile, and Python package boundary
for release and security hygiene work.

## Backend Package Boundary

The `vuln-prioritizer` backend distribution intentionally ships both:

- the shared domain package under `backend/src/vuln_prioritizer/**`
- the active Workbench FastAPI runtime under `backend/app/**`

This is the selected package story for the current tree. The package is
Workbench-first, and README/release wording should not imply that `app/*` is an
accidental inclusion or that the old CLI is the product direction.

The current package maturity classifier is `Development Status :: 4 - Beta`.
Treat that as local-first self-hosted Workbench readiness, not public internet
deployment certification. Moving to `Production/Stable` requires
candidate-specific release and deployment evidence with an explicit owner
handoff.

The package boundary is enforced by:

- `backend/pyproject.toml`, where `tool.setuptools.packages.find.include`
  includes both `vuln_prioritizer*` and `app*`
- `make package-check`, which builds the backend distributions, validates that
  their content includes every tracked Workbench Alembic migration through
  `scripts/check_package_contents.py`, runs `twine check`, installs the built
  wheel into a temporary virtualenv, imports `app.main:create_app`, and migrates
  a temporary Workbench database through Alembic head
- `build/package-contents.json`, generated locally by the package-content check

The sdist and wheel must contain `app/main.py`, `app/api/main.py`, the shared
`vuln_prioritizer` domain package, and the active Workbench Alembic migration
tree. They do not publish the old Typer CLI as a console entrypoint. They must
not include the backend test tree. They also must not reintroduce removed legacy
Workbench runtime packages under
`vuln_prioritizer/api`, `vuln_prioritizer/db`, or `vuln_prioritizer/web`.

## Coverage Boundary

The current backend pytest coverage gate in `backend/pyproject.toml` measures
both `vuln_prioritizer` and the active FastAPI Workbench package under
`backend/app`. This keeps the domain package and shipped API runtime inside the
same enforced release threshold.

Coverage configuration must stay aligned with the package boundary when modules
move. Package inclusion of `app*` is not coverage proof by itself; the pytest
coverage command must continue to measure both `app` and `vuln_prioritizer`.

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
Python 3.13 without dev extras. Keep all three committed together when Python
dependency metadata changes. The backend Docker image installs the local backend
package from `backend/pyproject.toml` with `--no-deps` after installing the
runtime lock, so runtime containers do not carry test, docs, or maintainer
tooling. `backend/requirements.lock.txt` remains the audited candidate
dependency set for release evidence.

GitHub workflows use Python 3.13 for single-version release, audit,
maintenance, provider-live, frontend, and CodeQL jobs so workflow evidence stays
aligned with the current Docker runtime. The CI Python matrix remains the
compatibility gate for every supported package version: 3.11, 3.12, and 3.13.
`make python-lock-check` enforces both the runtime lock export version and this
workflow Python policy.

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
  --python 3.13 --output-file backend/requirements.runtime.lock.txt --no-progress
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
cd frontend && npm --workspaces=false audit --audit-level=high
```

The frontend audit intentionally covers both runtime and dev/build-chain
dependencies from the committed lockfile. Do not exclude dev dependencies from
release or CI evidence unless the dependency policy is changed in the same
review.

The root workspace uses npm workspace scripts only. There is no tracked
`bun.lock`; adding one would need a package-manager policy change and should not
be used as release evidence unless that policy changes.

## Container Images

The checked-in Dockerfiles pin upstream base-image references with image
digests. Static external service images in Compose files are also pinned by
digest; locally built images that are parameterized through environment
variables stay unpinned because they point at the candidate image being built.
Keep the human-readable tag for maintenance context, but every checked external
image must also include `@sha256:...`. The local guard is:

```bash
make docker-base-image-check
```

The Docker workflow smoke-tests the built Workbench stack, emits SBOMs for the
backend and frontend images with digest-pinned Syft, emits full Grype JSON
reports, and gates Grype on fixable high/critical findings. Non-fixable
upstream base-image findings remain visible in the uploaded reports for
maintainer triage without making the required PR smoke permanently red. Public
production release evidence still needs candidate-specific image digests and
any required signing/provenance attestation for those exact images.

## Dependabot Labels

Dependabot PR labels must use labels that exist in the repository taxonomy.
The current automation label policy is:

| Ecosystem | Labels |
| --- | --- |
| Python backend | `maintenance`, `dependencies`, `python` |
| GitHub Actions | `maintenance`, `dependencies`, `github-actions` |
| Frontend npm | `maintenance`, `dependencies`, `type:frontend`, `area:ui` |

Closed dependency-update PRs are not carried forward as active policy tasks in
this document. When an ecosystem still needs a dependency refresh, track it in a
current issue or PR and remove the reference when the release gate accepts or
rejects the update.

## Release Evidence Commands

Use these commands when dependency or package policy changes:

```bash
make dependency-audit
make package-check
cd frontend && npm ci --workspaces=false
cd frontend && npm --workspaces=false audit --audit-level=high
```

Evidence must not include secrets, token values, cookies, customer exports,
private absolute paths, or shell history.
