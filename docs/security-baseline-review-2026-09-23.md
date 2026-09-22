# Security Baseline Review — 2026-09-23

This review is for the local-first, single-operator Workbench and its public
source repository. It is a prioritized engineering assessment, not a claim of
certification against a standard. The comparison uses the finalized
[NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final), the
[OpenSSF OSPS Baseline 2026.08.28](https://baseline.openssf.org/versions/2026-08-28),
and [SLSA 1.2](https://slsa.dev/spec/v1.2/). A full control-by-control compliance
assessment would require more evidence and is not needed for the current
deployment model.

## Controls already in place

| Area | Current evidence |
| --- | --- |
| Disclosure and repository access | `SECURITY.md` names supported versions and a private reporting route. Live GitHub settings on the review date showed private vulnerability reporting, Dependabot security updates, secret scanning, push protection, and strict protected-branch checks enabled. CodeQL runs for Python and TypeScript. |
| Known dependencies | `uv.lock`, two hashed Python requirement exports, and the npm lock support reproducible installs and `make dependency-audit`. Actions and container base images use digest or commit pins. |
| Container vulnerability evidence | `.github/workflows/docker.yml` generates SPDX inventories and Grype reports and retains them for 14 days. Its gate focuses on Critical or fixable High findings; a passing gate does not mean zero vulnerabilities. |
| Release and runtime | The release workflow verifies packages, runs smoke tests, creates SHA-256 checksums, and publishes GitHub assets as a draft. Configured PyPI publishing uses OIDC; whether a particular PyPI release was published and attested must be verified for that release. SQLite backups use an integrity-checked copy, and restore rejects unsafe archive members and active WAL destinations. |

## Remaining work, in order of practical value

1. **Make the dependency graph agree with the lock.** On the review date GitHub
   still associated five vulnerable historic versions with
   `backend/pyproject.toml`, while `uv.lock` and both hashed exports contained
   corrected versions. The package metadata also allowed older transitive
   versions on an unlocked install. Security minimums and a main-branch
   lock-derived dependency submission address these separate causes. Verify
   the actual [Dependabot alert states](https://docs.github.com/en/rest/dependabot/alerts)
   after the graph updates; an audit pass alone is insufficient. GitHub's
   [snapshot precedence rules](https://docs.github.com/en/rest/dependency-graph/dependency-submission)
   explain why duplicate graph inputs need special care.
2. **Bind inventories to delivered release artifacts.** The container workflow
   scans its images, but the wheel, source archive, and local release ZIP do
   not yet ship with their own retained SBOM and artifact-linked provenance.
   For the next public release, generate a machine-readable inventory from the
   actual built artifact, publish it alongside its digest, and verify the
   published asset against the intended commit. This is more useful here than
   adopting every possible SBOM format or a full SLSA level claim.
3. **Rehearse an operator restore with retained evidence.** The scripts and
   synthetic tests protect backup and restore logic, but there is no current
   dated proof that an operator's complete database, original uploads, and
   generated reports can be restored together. Set a practical recovery goal,
   keep a protected copy outside the workstation, then restore into an empty
   directory and verify the Decision Ledger and artifact hashes. Do not put
   real private backup content in CI or public release evidence.
4. **Align the release build with the audited Python resolution.** The release
   workflow currently installs `backend[dev]` from bounded metadata and builds
   in isolation, so its tooling can differ from the hashed audit export.
   Resolve release tooling from the reviewed lock and record the versions used
   for the exact published artifact. Keep package metadata ranges bounded so
   downstream users can receive compatible security fixes.
5. **Maintain pinned images and scanner versions.** Dependabot currently tracks
   pip, npm, and Actions. Add an update path for Docker base images and a
   periodic review of Syft/Grype pins; carry unfixed OS findings forward with
   their scanner and database version until an upstream fix is available.

SSO, role management, a second general-purpose scanner, and blanket VEX files
would add complexity without addressing these gaps for a trusted single
operator. A VEX statement is appropriate when a specific vulnerability's
affectedness can be justified for a specific released version.
