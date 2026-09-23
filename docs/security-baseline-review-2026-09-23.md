# Security Baseline Review — 2026-09-23

This review is for the local-first, single-operator Workbench and its public
source repository. It is a prioritized engineering assessment, not a claim of
certification against a standard. The comparison uses the finalized
[NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final), the
[OpenSSF OSPS Baseline 2026.08.28](https://baseline.openssf.org/versions/2026-08-28),
and [SLSA 1.2](https://slsa.dev/spec/v1.2/). A full control-by-control compliance
assessment would require more evidence and is not needed for the current
deployment model.

The original priorities below were revisited after
[PR #652](https://github.com/Noetheon/vuln-prioritizer-workbench/pull/652)
merged into `main` on 2026-09-23. The status section distinguishes implemented
controls from a successful preflight and from proof that still requires an
actual release or operator backup.

## Controls already in place

| Area | Current evidence |
| --- | --- |
| Disclosure and repository access | `SECURITY.md` names supported versions and a private reporting route. Live GitHub settings on the review date showed private vulnerability reporting, Dependabot security updates, secret scanning, push protection, and strict protected-branch checks enabled. CodeQL runs for Python and TypeScript. |
| Known dependencies | `uv.lock`, two hashed Python requirement exports, and the npm lock support reproducible installs and `make dependency-audit`. Actions and container base images use digest or commit pins. |
| Container vulnerability evidence | `.github/workflows/docker.yml` generates SPDX inventories and Grype reports and retains them for 14 days. Its gate focuses on Critical or fixable High findings; a passing gate does not mean zero vulnerabilities. |
| Release and runtime | The release workflow verifies packages, runs smoke tests, creates SHA-256 checksums, and can publish GitHub assets as a draft from a release tag. It now builds from the reviewed Python lock and generates archive-specific SPDX inventories and signed attestations. Configured PyPI publishing uses OIDC; whether a particular PyPI release was published and attested must be verified for that release. SQLite backup and restore include integrity checks and a synthetic full-restore rehearsal. |

## Dependency alert closure verified on main

At the start of this review GitHub associated five old vulnerable versions with
`backend/pyproject.toml`, while the committed locks already contained patched
versions. The metadata also permitted some older transitive versions on an
unlocked installation. [PR #650](https://github.com/Noetheon/vuln-prioritizer-workbench/pull/650)
added bounded security minimums and a main-branch submission of the actual
`uv.lock` graph. Its post-merge submission passed an offline lock consistency
check and GitHub accepted 128 resolved dependencies. A fresh GitHub SBOM export
then showed no historic vulnerable versions of AnyIO, SoupSieve, pip,
cryptography, or msgpack; every versioned entry for these five packages was
patched. The nine affected Dependabot alerts (#65, #66, #67, #75, #83,
#84, #85, #96, #97) all had state `fixed`, a non-null `fixed_at`, and null
`dismissed_at`; the open Dependabot, Code Scanning, and Secret Scanning counts
were each zero. This verifies repository alert closure, not that every
container or upstream OS vulnerability has a fix. See GitHub's
[snapshot precedence rules](https://docs.github.com/en/rest/dependency-graph/dependency-submission)
for why the lock-derived submission was needed.

## Follow-up status after PR #652

1. **Artifact-linked inventories and provenance: implemented, preflight
   verified.** The wheel, source archive, and local release ZIP receive SPDX
   inventories generated from their actual archive bytes, checksums, and signed
   GitHub provenance and SBOM attestations. The manual
   [Release preflight](https://github.com/Noetheon/vuln-prioritizer-workbench/actions/runs/35818889455)
   retained all three archives and their evidence. Their hashes, inventories,
   and attestations verified against the exact source commit and signer. The
   preflight commit has the same tree as merged `main`. No public release was
   published by this branch run; the tag-push upload and downloaded-asset checks
   remain to be verified on the next real release.
2. **Operator recovery: synthetic rehearsal passed; offsite proof outstanding.**
   The recovery script restored a current-schema synthetic database with its
   uploads and reports into an empty directory and checked its ledger and file
   integrity. There is still no dated restore proof for private operator data
   and no configured protected copy outside the workstation. Choose a backup
   destination and recovery objective, then retain a private restore record.
   Do not put private backup content in CI or public release evidence.
3. **Audited release build: implemented, preflight verified.** The workflow now
   checks `uv.lock`, installs the reviewed resolution, constrains the build with
   hashed requirements, and records tool versions and inputs for the built
   artifacts. The manual Release preflight passed this path. Publication of a
   specific version still requires its own release evidence.
4. **Pinned image and scanner maintenance: implemented, ongoing.** Dependabot
   now tracks Dockerfile and Compose images, and the scheduled Docker workflow
   checks pinned tag digests for changes. Image SBOMs and Grype reports remain
   retained. A passing gate does not erase unfixed OS findings; keep them in
   the scan evidence until an upstream fix is available.

SSO, role management, a second general-purpose scanner, and blanket VEX files
would add complexity without addressing these gaps for a trusted single
operator. A VEX statement is appropriate when a specific vulnerability's
affectedness can be justified for a specific released version.
