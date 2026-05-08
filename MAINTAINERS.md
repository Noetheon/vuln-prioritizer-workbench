# Maintainers

This file defines the public maintainer and ownership model for the repository.
It complements `.github/CODEOWNERS`, `CONTRIBUTING.md`, `SECURITY.md`, and the
GitHub-side repository settings that cannot be versioned in this checkout.

## Current Ownership

| Area | Primary owner | Notes |
| --- | --- | --- |
| Repository default ownership | `@Noetheon` | Mirrors `.github/CODEOWNERS`. |
| Security policy and disclosure routing | `@Noetheon` | Private security reports follow `SECURITY.md`. |
| Release evidence and package publication | `@Noetheon` | Release claims require current evidence in the release ledger. |
| Documentation architecture | `@Noetheon` | Current truth is owned through `docs/current-product-state.md` and `docs/documentation-map.md`. |

## Maintainer Responsibilities

Maintainers are expected to:

- keep the project focused on defensive prioritization of already-known CVEs
- protect the no-scanner, no-exploit, no-autopatcher, and no-heuristic
  ATT&CK-mapping boundaries
- review contributions through pull requests unless an emergency path is
  required
- require local or CI evidence for behavior, API, DB, frontend, docs, Docker,
  release, and security changes
- keep public documentation aligned with the active FastAPI/React Workbench and
  retained CLI/core package
- keep historical evidence clearly labelled as historical or demo evidence
- avoid public release or deployment claims that are not backed by current
  release-candidate evidence

## Review Expectations

Normal pull requests should include:

- a clear scope statement
- affected surfaces such as CLI, backend API, DB/migrations, frontend, Docker,
  docs, release, packaging, or security
- commands run and results
- screenshots, traces, generated-client drift checks, migration output, or
  release evidence when relevant
- residual risk and follow-up issues when something is intentionally deferred

Docs-only changes normally need `make docs-check`. Behavior changes normally
need `make check` plus narrower frontend, Docker, Playwright, release, or
security gates when those surfaces are touched.

## Release Ownership

Release candidates are not accepted from historical evidence alone. Before a
candidate is described as externally certified, maintainers must attach fresh
evidence for the exact commit, tag, or release candidate in the public release
ledger.

Required release evidence is tracked in
`docs/public-production-release-evidence-ledger.md` and
`docs/release_operations.md`.

## Escalation

- Usage and workflow questions follow `SUPPORT.md`.
- Security issues follow `SECURITY.md`.
- Conduct issues follow `CODE_OF_CONDUCT.md`.
- GitHub repository topics, branch protection, discussions, private
  vulnerability reporting, and trusted-publisher settings are configured on
  GitHub and tracked through `docs/github-open-source-readiness.md` and
  `docs/community_repository_setup.md`.
