# Release Operations

This document is the maintainer playbook for GitHub Releases and PyPI publishing.
It is intentionally operational: use it when cutting a release, restoring a missing release object, or enabling PyPI trusted publishing for the repository.

## Current Release Model

The repository ships releases through:

- a version tag such as `v1.1.0`
- the release workflow in [`release.yml`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/.github/workflows/release.yml)
- checked-in release notes under `docs/releases/`
- GitHub Release artifacts built from the tagged tree

The workflow already does the important trusted-publishing pieces:

- it builds source and wheel distributions
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
- TestPyPI publishing is available through the manual workflow [`.github/workflows/testpypi.yml`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/.github/workflows/testpypi.yml), is gated behind `TEST_PYPI_PUBLISH_ENABLED=true`, and verifies a hosted-index install after publish

That keeps normal tagged releases green even before PyPI Trusted Publishing is fully configured.

## Standard Tagged Release Flow

Use this path for normal releases:

1. Make sure the working tree is clean.
2. Run the local release gate while developing the candidate:

```bash
make release-check
```

3. Before tagging a release candidate, run and record the broader gate:

```bash
make release-readiness-check
```

This adds generated-client drift, demo evidence-bundle verification, and
Playwright smoke evidence to the normal release gate. It also runs the
production-like Docker smoke. It does not by itself close the VPW-AUD-999 final
scorecard.
For tagged releases, `.github/workflows/release.yml` runs this gate before any
GitHub Release or PyPI publish job can proceed.

4. Record the readiness evidence with owner-facing fields:

```text
Command:
Commit/tag:
Result:
Artifact or CI URL:
SHA-256 artifact list:
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
   artifacts.
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

1. Decide whether the target PyPI project will be the current distribution name `vuln-prioritizer`.
2. On PyPI, configure a Trusted Publisher for this repository and workflow.
3. Keep the GitHub environment name as `pypi` so the workflow and PyPI configuration stay aligned.
4. Set the repository variable `PYPI_PUBLISH_ENABLED=true` only after the trusted publisher is configured correctly.
5. If the project does not exist yet on PyPI, use PyPI's trusted-publisher project-creation flow or create the project first and then register the publisher.
6. Keep the PyPI publish job on GitHub limited to `id-token: write`; do not reintroduce long-lived API tokens.

## Post-Release Smoke Checks

After each public release:

1. Confirm the GitHub Release page exists and contains the built `sdist` and `wheel`.
2. Verify the documented GitHub tag install path:

```bash
pipx install git+https://github.com/Noetheon/vuln-prioritizer-workbench.git@vX.Y.Z#subdirectory=backend
printf 'CVE-2021-44228\n' > smoke-cves.txt
vuln-prioritizer analyze --input smoke-cves.txt --format json --output smoke.json
```

This validates the supported source-at-tag install path. It does not validate installation from the GitHub Release asset files themselves.

The tag-push release workflow now performs the same source-at-tag smoke automatically before publication. Keep the manual check here as an operator-level confirmation rather than the only verification step.

3. If PyPI is enabled, install from PyPI too:

```bash
pipx install "vuln-prioritizer==X.Y.Z"
printf 'CVE-2021-44228\n' > smoke-cves.txt
vuln-prioritizer analyze --input smoke-cves.txt --format json --output smoke.json
```

4. Confirm the README install instructions still match reality.
5. Confirm the release notes, tag, and GitHub Release object all use the same version string.
6. If the workflow already performed hosted-index verification, treat the manual install checks here as a second-line confirmation rather than the only release proof.

If TestPyPI is enabled, also verify the staging index first:

```bash
pipx install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  "vuln-prioritizer==X.Y.Z"
printf 'CVE-2021-44228\n' > smoke-cves.txt
vuln-prioritizer analyze --input smoke-cves.txt --format json --output smoke.json
```

## CI Cost Policy

The repository keeps PR safety checks active while reducing duplicate and
long-running GitHub Actions work.

Pull requests to `main` run the Python workflow gate, local action smoke,
frontend lint/build/client drift checks, Playwright smoke coverage, Docker
workflow status, and CodeQL where configured. Docs/archive-only PRs still get a
successful Docker workflow, but the expensive Docker compose build is skipped
after the workflow confirms that only non-runtime paths changed.

The CI frontend gate runs for frontend, API, generated-client, runtime, and CI
gate changes. It runs lint, build, unit tests, generated-client drift, and
bounded Playwright smoke/responsive/accessibility specs. Docs/archive-only PRs
still get an explicit successful skip.

The Docker workflow runs `make docker-demo-smoke` for backend, Compose, Docker,
dependency, runtime script, frontend build-config, and Docker workflow changes.
That smoke covers health, login, authenticated readiness, locked-provider import,
findings, and provider status. Docs/archive-only PRs still get an explicit
successful skip, and failures print compose status/logs.

Pushes to `main` run the post-merge version of the same CI workflows. The
frontend job runs the full Playwright suite on `main`, while PRs run bounded
smoke, responsive, and accessibility specs for faster feedback. Manual
`workflow_dispatch` remains available for full validation of CI, Docker,
maintenance, release, and TestPyPI paths.

The main cost controls are:

- stale workflow runs are cancelled after newer pushes;
- feature-branch push workflows are not duplicated when a PR already validates
  the same commit;
- full Playwright runs on `main` and manual CI, while PRs use smoke,
  responsive, and accessibility coverage;
- Docker compose is skipped for docs/archive-only changes;
- failure/debug artifacts use short retention windows.

The tradeoff is that route-specific Playwright regressions outside the bounded
PR specs may be discovered after merge instead of during every PR. The PR gate
still covers core route rendering, responsive shell behavior, accessibility, and
runtime-impacting Docker paths.

## Required Contexts And Ownership

Branch protection should treat these release-adjacent contexts as required for
release or runtime PRs:

- `CI / check (3.12)` for the local-equivalent Python workflow gate.
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
- Keep the package story aligned with [Dependency and Package Policy](./dependency-and-package-policy.md): the backend distribution intentionally ships both the CLI/core package and active `backend/app` Workbench runtime.
- Keep public-production release evidence aligned with [Public-Production Release Evidence Ledger](./public-production-release-evidence-ledger.md).
- If PyPI goes live, update the README and release docs immediately so GitHub-tag install is no longer described as the only verified public path.
