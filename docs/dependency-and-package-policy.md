# Dependency and Package Policy

This page defines the current dependency, lockfile, and Python package boundary
for release and security hygiene work.

## Backend Package Boundary

The `vuln-prioritizer-workbench` backend distribution intentionally ships one
Workbench namespace:

- the active FastAPI runtime, SQL models, services, migrations, and internal
  engine under `backend/app/**`

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
  includes only `app*`
- `make package-check`, which builds the backend distributions, validates that
  their content includes every tracked Workbench Alembic migration, packaged
  frontend asset, and required runtime resource through
  `scripts/check_package_contents.py`, runs `twine check`, installs the built
  wheel into a temporary virtualenv, invokes the `vpw` entrypoint, imports
  `app.main:create_app`, mounts the frontend, and migrates a temporary Workbench
  database through Alembic head
- `build/package-contents.json`, generated locally by the package-content check

The sdist and wheel must contain `app/cli.py`, `app/main.py`, `app/api/main.py`,
`app/domain/engine/**`, `app/static/**`, `app/resources/**`, and the active
Workbench Alembic migration tree. The `vpw` console script starts or maintains
the browser Workbench; it does not publish the old Typer analytical CLI. The
distributions must not include the backend test tree or reintroduce removed legacy Workbench
runtime packages under
`app/domain/engine/api`, `app/domain/engine/db`, or `app/domain/engine/web`.

`scripts/sync_runtime_assets.py` is the package boundary between source assets
and installed runtime assets. `make runtime-assets-check` must prove that
`frontend/dist` and selected local provider/ATT&CK resources match the packaged
copies. Generated runtime assets are release inputs and must be refreshed after
every frontend build or selected-resource change.

## Coverage Boundary

The current backend pytest coverage configuration in `backend/pyproject.toml`
measures the active Workbench package under `backend/app`. `pytest-cov` owns
measurement and the terminal report, while the enforced backend gate is
`make critical-coverage-check` over the generated coverage JSON. This avoids a
misleading total-project fail-under message while still protecting the critical
Workbench modules.

Coverage configuration must stay aligned with the package boundary when modules
move. Package inclusion of `app*` is not coverage proof by itself; pytest must
continue to measure `app`, and `make check` must continue to generate
`build/coverage-current.json` before running the critical coverage gate.

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
uv export --format requirements.txt --package vuln-prioritizer-workbench --no-dev \
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
scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true ci
scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true audit --audit-level=high
```

Frontend commands must run on Node 22 with npm 10. The repository carries the
same policy in `.tool-versions`, root `package.json`, `frontend/package.json`,
GitHub Actions `setup-node`, root `.npmrc`, and the root-owned Make frontend
command wrapper. Run ad hoc frontend npm commands from the repository root with
`scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true`
or the equivalent Make target so the frontend package's engine policy is
enforced consistently. The explicit flag is required because npm prefix commands
do not reliably inherit the root `.npmrc`. Do not add a workspace-local
`frontend/.npmrc`; npm ignores workspace config for workspace script execution
and emits warning noise instead of improving enforcement.
Docker frontend builds must use the same explicit engine-strict install and
build flags so container evidence cannot silently diverge from CI/local npm
policy.

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

The same Docker workflow also runs weekly in full mode. That scheduled run is
the CVE-drift backstop for pinned base images: normal PRs only pay for image
security when Docker, dependency, Compose, Grype, or build-policy inputs change,
while new fixable high/critical findings are still surfaced without waiting for
the next container-related pull request.

Any Grype ignore in `.grype.yaml` must be narrow, documented, and temporary.
Use it only for upstream base-image findings where the scanner reports a fix
outside the repository's current stable runtime policy, such as a beta-only
Python fix while the Docker runtime remains pinned to stable Python 3.13.

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
scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true ci
scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true audit --audit-level=high
```

Evidence must not include secrets, token values, cookies, customer exports,
private absolute paths, or shell history.
