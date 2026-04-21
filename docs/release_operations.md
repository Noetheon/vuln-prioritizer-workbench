# Release Operations

This document is the maintainer playbook for GitHub Releases and PyPI publishing.
It is intentionally operational: use it when cutting a release, restoring a missing release object, or enabling PyPI trusted publishing for the repository.

## Current Release Model

The repository currently ships releases through:

- a version tag such as `v1.1.0`
- the release workflow in [`release.yml`](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/.github/workflows/release.yml)
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
- TestPyPI publishing is available through the manual workflow [`.github/workflows/testpypi.yml`](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/.github/workflows/testpypi.yml), is gated behind `TEST_PYPI_PUBLISH_ENABLED=true`, and verifies a hosted-index install after publish

That keeps normal tagged releases green even before PyPI Trusted Publishing is fully configured.

## Standard Tagged Release Flow

Use this path for normal releases:

1. Make sure the working tree is clean.
2. Run the local release gate:

```bash
make release-check
```

3. Create or update the checked-in release notes file:

```text
docs/releases/vX.Y.Z.md
```

4. Tag the release:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin main
git push origin vX.Y.Z
```

5. Confirm that the GitHub Release workflow completed successfully.
6. If PyPI publishing is enabled for the repository, verify that the package appeared on PyPI.
7. Confirm that the workflow's hosted-index install verification step completed successfully.

## Restoring a Missing GitHub Release Object

If a tag exists but the GitHub Release object is missing, recreate it from the current tag:

```bash
python3 -m build
gh release create vX.Y.Z dist/* \
  --title vX.Y.Z \
  --notes-file docs/releases/vX.Y.Z.md
```

This is the correct recovery path after accidental GitHub-side deletion or repository history cleanup, as long as the release tag still points to the intended tree.

## TestPyPI Validation Path

Before the first public PyPI publish, validate the packaging and trusted-publisher path through the manual TestPyPI workflow:

1. Configure a trusted publisher for TestPyPI that matches:
   - GitHub owner: `Noetheon`
   - Repository: `vuln-prioritizer-cli`
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
- Repository: `vuln-prioritizer-cli`
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
pipx install git+https://github.com/Noetheon/vuln-prioritizer-cli.git@vX.Y.Z
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

## Failure Modes To Check First

If the PyPI publish job fails, check these before anything else:

- the trusted publisher matches the exact repository and workflow file
- the trusted publisher uses the same `pypi` environment as the GitHub workflow
- the repository variable `PYPI_PUBLISH_ENABLED` is set to `true`
- the publish job still has `id-token: write`
- the tag and checked-in release notes refer to the same version
- the built artifacts pass `twine check`

## Maintainer Notes

- Keep this document in sync with [`release.yml`](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/.github/workflows/release.yml).
- Keep the public install wording in [`README.md`](https://github.com/Noetheon/vuln-prioritizer-cli/blob/main/README.md) aligned with the real supported install path.
- If PyPI goes live, update the README and release docs immediately so GitHub-tag install is no longer described as the only verified public path.
