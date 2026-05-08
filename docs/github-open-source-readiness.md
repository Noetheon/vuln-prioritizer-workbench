# GitHub Open Source Readiness

This page is the public GitHub-facing documentation map for repository health,
community entrypoints, contribution flow, security reporting, and release-claim
boundaries.

Use [Current Product State](current-product-state.md) for product truth and
[Documentation Map](documentation-map.md) for documentation ownership. Use this
page when deciding whether the GitHub repository surface is coherent for
external readers and contributors.

## Visitor Entry Points

| Need | Entry point | Notes |
| --- | --- | --- |
| Understand the project quickly | [`README.md`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/README.md) | Public overview, quickstarts, safety boundaries, docs links, and project status. |
| Find the canonical product truth | [Current Product State](current-product-state.md) | Active stack, user surfaces, release posture, and historical boundaries. |
| Use the CLI or Workbench | [User Documentation Guide](user_documentation.md) | Full external-user path across install, Docker, CLI, Workbench, providers, reports, and limitations. |
| Check supported inputs and outputs | [Support Matrix](support_matrix.md) | Import formats, report formats, evidence outputs, and feature overlays. |
| Understand stable contracts | [Contracts](contracts.md) | CLI, report, evidence bundle, API, and schema contract details. |
| Contribute safely | [`CONTRIBUTING.md`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/CONTRIBUTING.md) | Local setup, quality gates, branch/PR rules, and scope guardrails. |
| Ask for help | [`SUPPORT.md`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/SUPPORT.md) | Issue, discussion, and security-report routing. |
| Report security issues | [`SECURITY.md`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/SECURITY.md) | Private disclosure path and project-specific security notes. |
| Understand conduct expectations | [`CODE_OF_CONDUCT.md`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/CODE_OF_CONDUCT.md) | Community behavior and conduct escalation. |
| Understand ownership | [`MAINTAINERS.md`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/MAINTAINERS.md) and [`.github/CODEOWNERS`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/.github/CODEOWNERS) | Maintainer responsibilities and default review ownership. |
| Review releases | [`CHANGELOG.md`](https://github.com/Noetheon/vuln-prioritizer-workbench/blob/main/CHANGELOG.md), [Release Operations](release_operations.md), and [Release Evidence Ledger](public-production-release-evidence-ledger.md) | Historical changes, release workflow, evidence requirements, and residual-risk tracking. |

## Community Health Files

GitHub can surface these files automatically when they exist on the default
branch:

- `README.md`
- `LICENSE`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `CODE_OF_CONDUCT.md`
- `SUPPORT.md`
- `CHANGELOG.md`
- `MAINTAINERS.md`
- `.github/CODEOWNERS`
- `.github/ISSUE_TEMPLATE/*.md`
- `.github/ISSUE_TEMPLATE/config.yml`
- `.github/pull_request_template.md`

These files are versioned. Repository settings such as discussions, branch
protection, private vulnerability reporting, repository topics, homepage,
trusted publishing, and security features must still be checked on GitHub.

## Issue Routing

Use public issues for reproducible public work:

- bugs with sanitized reproduction steps
- feature requests with a clear user or maintainer problem
- parser/provider/import-format changes with small sanitized fixtures
- documentation fixes
- security hardening requests that do not disclose a private vulnerability

Do not use public issues for:

- vulnerability disclosures with sensitive reproduction detail
- customer exports, private scan data, tokens, cookies, or internal hostnames
- exploit payloads or public proof-of-concept detail
- requests that would turn the project into a scanner, exploit framework,
  credential tester, hosted SaaS workflow, autopatcher, or heuristic
  CVE-to-ATT&CK mapper

Private vulnerability reporting follows `SECURITY.md`.

## Pull Request Quality Bar

A reviewable pull request should include:

- a concise summary and linked issue or roadmap ID when relevant
- changed surfaces: CLI, backend API, DB/migrations, generated client, frontend,
  Docker, docs, release, packaging, or security
- exact commands run and result summaries
- generated artifacts or screenshots when the changed surface needs them
- residual risk and follow-up issues when something remains open
- release-readiness evidence when the PR affects release, deployment, public
  documentation claims, Docker, package publication, or security boundaries

The pull request template encodes this checklist. Maintainers should not close
strict evidence issues from old notes, archived screenshots, or historical demo
proof without fresh evidence for the current candidate.

## Documentation Quality Bar

Public docs are acceptable for GitHub only when they preserve these boundaries:

- one canonical product truth in [Current Product State](current-product-state.md)
- one documentation ownership map in [Documentation Map](documentation-map.md)
- clear current vs historical separation in `mkdocs.yml`
- no overclaiming of public deployment certification from local quickstarts
- archive links labelled as historical evidence or demo snapshots unless a
  current release page explicitly scopes them as current evidence
- tracked archive binaries pinned in `archive/vpw-evidence/BINARY-MANIFEST.json`
- `make docs-check` passing before handoff

## Release And Deployment Claim Boundary

The repository can document a release process, local validation, and expected
public deployment evidence. It cannot prove a live public deployment only from
checked-in Markdown.

Before an external deployment claim is made for a release candidate, the public
release ledger must include fresh evidence for that exact candidate:

- `make release-readiness-check` or a documented equivalent with owner-approved
  skip rationale
- public TLS/header captures from the deployed host
- Traefik/proxy topology evidence
- strict CORS, cookie, CSRF, and security-header behavior
- backup/restore, schema readiness, retention, and audit evidence where relevant
- dependency and container/image posture evidence
- residual-risk decision with owner and follow-up

## GitHub-Side Settings Checklist

These settings are not created by files in this repository. Maintainers should
verify them in GitHub before broad public launch or release promotion:

- repository description and topics match the current Workbench plus CLI scope
- homepage points to stable docs or is intentionally empty
- discussions are enabled only if they are actively supported
- wiki is disabled if versioned docs remain canonical
- delete-branch-on-merge is enabled
- `main` is protected against force-push and deletion
- required checks match the real CI policy
- secret scanning, push protection, vulnerability alerts, Dependabot, and CodeQL
  are enabled where available
- private vulnerability reporting is enabled if `SECURITY.md` points to it
- PyPI and TestPyPI trusted-publisher settings match the release workflows

The detailed maintainer checklist lives in
[Community And Public Repository Setup](community_repository_setup.md).

## Current Scope And External Checks

The repository documentation now defines the expected open-source GitHub surface
for a security tool: clear README, license, contribution path, support path,
security policy, conduct policy, maintainer ownership, changelog, roadmap, docs
site, issue/PR templates, release evidence boundaries, and automated docs
checks.

The remaining public-release work is outside pure documentation: attach live
release-candidate deployment evidence, confirm GitHub-side settings, and add
image supply-chain evidence for releases.
