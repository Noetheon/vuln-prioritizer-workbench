# Release Operations

This document is the maintainer playbook for GitHub Releases and PyPI publishing.
It is intentionally operational: use it when cutting a release, restoring a missing release object, or enabling PyPI trusted publishing for the repository.

## Current Release Model

The repository ships releases through:

- a version tag such as `v1.1.0`
- the release workflow in [`release.yml`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/.github/workflows/release.yml)
- checked-in release notes under `docs/releases/`
- GitHub Release artifacts built from the tagged tree

Release evidence must use the exact tag or commit. The repository contains
inherited historical/template-line `0.x` tags, so `0.x` names in older roadmap
or changelog material are not sufficient proof of current VPW behavior. Verify
the exact tag with `git for-each-ref refs/tags` and prefer the current VPW
package release tag `v1.1.0` for Workbench-era release evidence.

The current package metadata uses `Development Status :: 4 - Beta`, meaning
local-first self-hosted Workbench readiness, with shared domain code in the
package, but without public-production certification. Changing that
classifier to `Production/Stable` requires the same candidate-specific evidence
and residual-risk decision used for the public-production release ledger.

The workflow already does the important trusted-publishing pieces:

- it builds source and wheel distributions
- it builds the local end-user Workbench ZIP through `make release-bundle`
- it validates them with `twine check`
- it publishes a GitHub Release from the checked-in notes when present
- it uses `pypa/gh-action-pypi-publish@release/v1`
- it grants `id-token: write` on the PyPI job
- it runs the PyPI job inside the `pypi` GitHub environment

Current safety model:

- tagged releases always build artifacts and publish the GitHub Release
- manual `workflow_dispatch` runs on the release workflow are preflight-only and do not create a GitHub Release or publish to PyPI
- public PyPI publishing is gated behind the repository variable `PYPI_PUBLISH_ENABLED=true`
- the live PyPI workflow verifies a hosted-index install after publish
- TestPyPI publishing is available through the manual workflow [`.github/workflows/testpypi.yml`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/.github/workflows/testpypi.yml), runs `make release-readiness-check`, is gated behind `TEST_PYPI_PUBLISH_ENABLED=true`, and verifies a hosted-index install after publish

That keeps normal tagged releases green even before PyPI Trusted Publishing is fully configured.

## Standard Tagged Release Flow

Use this path for normal releases:

1. Make sure the working tree is clean.
2. Run the local release gate while developing the candidate:

```bash
make release-check
```

3. Before tagging a release candidate, run and record the broader local gate:

```bash
make release-readiness-check
```

This adds generated-client drift, archive binary evidence validation,
Playwright smoke evidence, and package smoke validation to the normal release
gate. It also runs the production-like Docker smoke. It does not by itself
certify a public deployment: live public TLS/header evidence and the explicit
public deployment evidence contract still have to be captured for the exact
deployed candidate.
For tagged releases, `.github/workflows/release.yml` runs this gate before any
GitHub Release or PyPI publish job can proceed.

The VPW-AUD-999 final scorecard closed on 2026-05-08, but historical PP
artifacts or local ignored build outputs must not be reused as current release
evidence. Link fresh output or CI artifacts for the exact commit, tag, or
release candidate before recording the final residual-risk decision.

4. Record the readiness evidence with owner-facing fields:

```text
Command:
Commit/tag:
Result:
Artifact or CI URL:
SHA-256 artifact list:
Public TLS/header evidence:
Archive binary manifest:
Residual risk:
Owner:
Follow-up:
```

Allowed skips must use non-readiness wording and include an owner, rationale,
residual risk, and follow-up issue. Do not describe a skipped candidate as
ready. The release owner is responsible for pasting the evidence comment into
the PR, release issue, or release ledger before tagging.

5. Create or update the checked-in release notes file:

```text
docs/releases/vX.Y.Z.md
```

6. Tag the release:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin main
git push origin vX.Y.Z
```

7. Confirm that the GitHub Release workflow completed successfully.
8. Download or link the `release-readiness-evidence` workflow artifact. It must
   include the release-readiness command log, commit metadata, evidence-bundle
   verification JSON when generated, and the SHA-256 list for built release
   artifacts, including the local Workbench ZIP.
9. If PyPI publishing is enabled for the repository, verify that the package appeared on PyPI.
10. Confirm that the workflow's hosted-index install verification step completed successfully.

## Restoring a Missing GitHub Release Object

If a tag exists but the GitHub Release object is missing, recreate it from the current tag:

```bash
make package
gh release create vX.Y.Z dist/* \
  --title vX.Y.Z \
  --notes-file docs/releases/vX.Y.Z.md
```

`make package` removes stale `dist/` artifacts and runs
`python3 -m build backend --outdir dist`, matching the GitHub release and
TestPyPI workflows. Run `make package-check` first when the recovery needs a
fresh local packaging validation before recreating the GitHub Release object.
This is the correct recovery path after accidental GitHub-side deletion or
repository history cleanup, as long as the release tag still points to the
intended tree.

## TestPyPI Validation Path

Before the first public PyPI publish, validate the packaging and trusted-publisher path through the manual TestPyPI workflow:

1. Configure a trusted publisher for TestPyPI that matches:
   - GitHub owner: `Noetheon`
   - Repository: `vuln-prioritizer-workbench`
   - Workflow file: `.github/workflows/testpypi.yml`
   - GitHub environment: `testpypi`
2. Set the repository variable `TEST_PYPI_PUBLISH_ENABLED=true`.
3. Run the `TestPyPI Publish` workflow manually from GitHub Actions.
4. Verify that the distributions appear on TestPyPI.
5. Confirm that the workflow's hosted-index install verification step completed successfully.
6. Optionally repeat the install manually before enabling real PyPI publication.

## PyPI Trusted Publishing Checklist

The repository is already wired for PyPI Trusted Publishing in the workflow.
The remaining setup is GitHub-side and PyPI-side configuration.

### Workflow Values To Match On PyPI

When configuring the trusted publisher on PyPI, match these repository values:

- GitHub owner: `Noetheon`
- Repository: `vuln-prioritizer-workbench`
- Workflow file: `.github/workflows/release.yml`
- GitHub environment: `pypi`
- Repository variable to enable the publish job: `PYPI_PUBLISH_ENABLED=true`

### Setup Steps

1. Decide whether the target PyPI project will be the current distribution name `vuln-prioritizer-workbench`.
2. On PyPI, configure a Trusted Publisher for this repository and workflow.
3. Keep the GitHub environment name as `pypi` so the workflow and PyPI configuration stay aligned.
4. Set the repository variable `PYPI_PUBLISH_ENABLED=true` only after the trusted publisher is configured correctly.
5. If the project does not exist yet on PyPI, use PyPI's trusted-publisher project-creation flow or create the project first and then register the publisher.
6. Keep the PyPI publish job on GitHub limited to `id-token: write`; do not reintroduce long-lived API tokens.

## Post-Release Smoke Checks

After each public release:

1. Confirm the GitHub Release page exists and contains the built `sdist`,
   `wheel`, `vuln-prioritizer-workbench-local-X.Y.Z.zip`, and ZIP SHA-256 file.
2. Verify the release bundle locally:

```bash
tmpdir="$(mktemp -d)"
unzip vuln-prioritizer-workbench-local-X.Y.Z.zip -d "$tmpdir"
cd "$tmpdir"/vuln-prioritizer-workbench-local-X.Y.Z
bash scripts/launch-workbench.sh status
```

This validates that the release asset contains the launchers, Compose files,
source tree, and `BUNDLE-MANIFEST.json`. Run `bash scripts/launch-workbench.sh
start` for a full Docker launch verification when Docker is available.

3. Verify the documented GitHub tag install path:

```bash
tmpdir="$(mktemp -d)"
python3 -m venv "$tmpdir/venv"
"$tmpdir/venv/bin/python" -m pip install \
  "git+https://github.com/Noetheon/vuln-prioritizer-workbench.git@vX.Y.Z#subdirectory=backend"
"$tmpdir/venv/bin/python" scripts/workbench_wheel_smoke.py \
  "$tmpdir/workbench-source-smoke.json"
```

This validates the supported source-at-tag install path and the installed
Workbench app/Alembic package contents. It does not validate installation from
the GitHub Release asset files themselves.

The tag-push release workflow performs the same source-at-tag Workbench smoke
automatically before publication. Keep the manual check here as an
operator-level confirmation rather than the only verification step.

4. If PyPI is enabled, install from PyPI too:

```bash
tmpdir="$(mktemp -d)"
python3 -m venv "$tmpdir/venv"
"$tmpdir/venv/bin/python" -m pip install "vuln-prioritizer-workbench==X.Y.Z"
"$tmpdir/venv/bin/python" scripts/workbench_wheel_smoke.py \
  "$tmpdir/workbench-pypi-smoke.json"
```

5. Confirm the README, `INSTALL.md`, and `TROUBLESHOOTING.md` instructions still match reality.
6. Confirm the release notes, tag, and GitHub Release object all use the same version string.
7. If the workflow already performed hosted-index verification, treat the manual install checks here as a second-line confirmation rather than the only release proof.

If TestPyPI is enabled, also verify the staging index first:

```bash
tmpdir="$(mktemp -d)"
python3 -m venv "$tmpdir/venv"
"$tmpdir/venv/bin/python" -m pip download \
  --no-deps \
  --only-binary=:all: \
  --index-url https://test.pypi.org/simple/ \
  --dest "$tmpdir" \
  "vuln-prioritizer-workbench==X.Y.Z"
"$tmpdir/venv/bin/python" -m pip install "$tmpdir"/vuln_prioritizer_workbench-X.Y.Z-*.whl
"$tmpdir/venv/bin/python" scripts/workbench_wheel_smoke.py \
  "$tmpdir/workbench-testpypi-smoke.json"
```

## CI Cost Policy

The repository keeps PR safety checks active while reducing duplicate and
long-running GitHub Actions work.

Ready pull requests to `main` run the Python workflow gate, package smoke,
frontend lint/build/client drift checks with coverage, scoped Playwright
coverage for frontend/API/runtime-impacting changes, Docker workflow status, and
CodeQL where configured. Docs/archive-only PRs still get successful frontend and
Docker workflow contexts, but the expensive browser and Docker compose work is
skipped after the workflows confirm that only non-runtime paths changed.

The CI frontend gate runs for frontend, API, generated-client, runtime, Node/npm
toolchain policy, and CI gate changes. It runs lint, build, unit tests,
generated-client drift, and Playwright. Backend/API-only PRs use Chromium and
mobile Chromium; UI, style, browser-config, `main`, and manual runs keep the
full browser and visual-regression path. Docs/archive-only PRs still get an
explicit successful skip.

The Docker workflow runs `make docker-demo-smoke` for backend, dependency,
runtime script, Node/npm toolchain policy, and frontend build-config changes. It
adds `make docker-production-smoke` for Compose, Dockerfile, nginx,
production-smoke, runtime config, Makefile, and Docker workflow changes. Image
SBOM and Grype scans run for dependency, Dockerfile, Compose, Grype, Makefile,
and Docker workflow changes. Those gates cover health, local readiness,
locked-provider import, findings, provider status, Postgres
Alembic/schema/repository readiness, same-origin production routing, security
headers, report download, path redaction, and image vulnerability policy.
Docs/archive-only PRs still get an explicit successful skip, and failures print
compose status/logs.

Pushes to `main` run the post-merge version of the same CI workflows. Manual
`workflow_dispatch` remains available for full validation of CI, Docker,
maintenance, release, and TestPyPI paths.

The main cost controls are:

- stale workflow runs are cancelled after newer pushes;
- feature-branch push workflows are not duplicated when a PR already validates
  the same commit;
- ready PRs scope expensive frontend and Docker work according to changed
  runtime/browser/container inputs;
- draft PRs keep successful required contexts where possible and rerun the full
  ready-state gates on the `ready_for_review` event;
- Docker compose is skipped for docs/archive-only changes;
- failure/debug artifacts use short retention windows.

The tradeoff is cost and runtime: UI/browser PRs still pay for full browser and
visual-regression coverage before merge, while backend/API-only PRs get
representative Playwright coverage. Draft PRs remain the intentional exception
until the PR is marked ready for review.

## Required Contexts And Ownership

Branch protection should treat these release-adjacent contexts as required for
release or runtime PRs:

- `CI / check (3.11)` for the local-equivalent Python workflow gate.
- `CI / frontend` for frontend/API/runtime representative browser evidence.
- `Docker / compose-smoke` for runtime and Compose evidence.
- CodeQL where repository security policy requires it.

The release workflow is not a branch-protection context because it runs on tags,
but tagged releases cannot publish unless `make release-readiness-check` passes
inside `.github/workflows/release.yml`. Any exception before tagging must name
the release owner, rationale, residual risk, follow-up issue, and the exact
non-readiness wording to use in release communications.

## Failure Modes To Check First

If the PyPI publish job fails, check these before anything else:

- the trusted publisher matches the exact repository and workflow file
- the trusted publisher uses the same `pypi` environment as the GitHub workflow
- the repository variable `PYPI_PUBLISH_ENABLED` is set to `true`
- the publish job still has `id-token: write`
- the tag and checked-in release notes refer to the same version
- the built artifacts pass `twine check`

## Maintainer Notes

- Keep this document in sync with [`release.yml`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/.github/workflows/release.yml).
- Keep the public install wording in [`README.md`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/README.md) aligned with the real supported install path.
- Keep the package story aligned with [Dependency and Package Policy](./dependency-and-package-policy.md): the backend distribution intentionally ships both the shared domain package and active `backend/app` Workbench runtime.
- Keep public-production release evidence aligned with [Public-Production Release Evidence Ledger](./public-production-release-evidence-ledger.md).
- If PyPI goes live, update the README and release docs immediately so GitHub-tag install is no longer described as the only verified public path.
