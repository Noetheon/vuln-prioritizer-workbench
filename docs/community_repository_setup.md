# Community And Public Repository Setup

This document is a maintainer checklist for running `vuln-prioritizer-workbench` as a
public GitHub repository. It is intentionally scoped to a security-focused local
Workbench for prioritizing known CVEs, not a general scanner, SaaS platform, or
community program.

Use it for two different jobs:

- keep the local repository documentation consistent
- configure the small set of GitHub-side settings that cannot be created from files in this repo

For the public reader-facing map of GitHub entrypoints and repository health,
start with [GitHub Open Source Readiness](./github-open-source-readiness.md).

## What Lives Where

The split matters:

| Item | Where it is managed | Notes |
| --- | --- | --- |
| `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`, `MAINTAINERS.md`, `CHANGELOG.md` | local docs in the repo | Versioned guidance. GitHub can surface several of these automatically; README and docs link the rest. |
| [docs/github-open-source-readiness.md](./github-open-source-readiness.md) | local doc in the repo | Public GitHub-facing map for community health, routing, and claim boundaries. |
| `.github/ISSUE_TEMPLATE/*.md` and `.github/ISSUE_TEMPLATE/config.yml` | local files in the repo | Versioned templates and contact links. GitHub uses them after they land on the default branch. |
| [docs/release_operations.md](./release_operations.md) | local doc in the repo | Maintainer runbook for GitHub Releases and PyPI publishing. |
| This document | local doc in the repo | Maintainer reference only. It does not create labels, topics, or repository settings by itself. |
| Repository topics | GitHub UI or API | Must be configured on GitHub. |
| Label definitions and colors | GitHub UI or API | Must be configured on GitHub. Template front matter can reference labels, but it does not create them. |
| Repository visibility and surface settings | GitHub UI or API | Public/private state, discussions, wiki, homepage, merge cleanup, and related toggles must be configured on GitHub. |
| Private vulnerability reporting or security advisories settings | GitHub repository settings | Must be configured on GitHub if the project wants GitHub-managed private reporting in addition to `SECURITY.md`. |

## Recommended Launch Metadata

Use this public metadata unless the repository settings deliberately differ:

- visibility: `PUBLIC`
- default branch: `main`
- description: `Local-first workbench for explainable CVE prioritization from scanner, SBOM, VEX, and asset evidence.`
- homepage: empty until a stable docs, release, or project page URL exists
- social preview: upload `docs/examples/media/github-social-preview.png` in the
  repository settings
- projects: disabled unless a maintained public GitHub Project board is active
- packages: unused unless a release explicitly publishes container or package
  artifacts through GitHub Packages

Recommended external-share title:

```text
Vuln Prioritizer Workbench: local-first CVE triage with EPSS, KEV, SBOM/VEX, and evidence reports
```

Recommended external-share summary:

```text
Open-source local-first Workbench that imports existing CVE evidence, explains
remediation priority with CVSS/EPSS/KEV plus asset and VEX context, and exports
auditable reports and evidence bundles. It is defensive prioritization software,
not a scanner, exploit tool, hosted SaaS, or AI scoring black box.
```

Before broader public launch, recheck GitHub-side settings after repository
moves, renames, release automation changes, or docs-site publication.

## Recommended Repository Topics

Start with a small topic set that accurately describes the project:

- `python`
- `workbench`
- `security`
- `cve`
- `cvss`
- `epss`
- `cisa-kev`
- `mitre-attack`
- `vulnerability-management`
- `risk-based-vulnerability-management`
- `sbom`
- `vex`
- `sarif`
- `devsecops`
- `security-tools`
- `docker`

Optional topics when they reflect the current release surface:

- `cyclonedx`
- `fastapi`
- `react`
- `local-first`
- `sqlite`

Avoid adding adjacent-but-misleading topics such as `scanner`, `siem`, `edr`, or
`threat-intelligence-platform`. The project is a local-first prioritization
Workbench for known CVEs, not a scanning engine or broad security platform.

## Recommended Label Taxonomy

Keep the label set current with the GitHub repository taxonomy. The goal is
routing and contributor clarity, not process theater.

### Core Type Labels

These should exist before opening the repo to wider contribution:

| Label | Use when | Notes |
| --- | --- | --- |
| `bug` | behavior is incorrect, regressed, or broken | Already used by the bug issue template. |
| `type:feature` | a scoped product improvement is requested | Used by the feature request template. |
| `type:parser` | parser, import-format, normalized-occurrence, or Workbench import workflow work | Used by the parser/import issue template. |
| `type:provider` | enrichment provider, cache, snapshot, or provider freshness work | Used by the provider issue template. |
| `type:attack` | defensive ATT&CK/TTP mapping, provenance, Navigator, or coverage review | Used by the ATT&CK mapping review template. |
| `type:docs` | the main work is docs, examples, or guidance | Good candidate for low-risk external contributions. |
| `type:task` | engineering work without standalone user-facing value | Useful for roadmap, cleanup, and validation tracking. |
| `type:security` | security hardening, threat modeling, or secure defaults | Public disclosures still use `SECURITY.md`, not public issue details. |
| `maintenance` | dependency, CI, release, packaging, or cleanup work | Use for repo upkeep that is not user-facing behavior. |

### Community Labels

These help contributors self-select:

| Label | Use when | Notes |
| --- | --- | --- |
| `good first issue` | a newcomer can complete the work with clear file pointers and a local verification path | Do not use for provider, scoring, or ATT&CK design work unless the change is tightly bounded. |
| `help wanted` | maintainers actively want outside help and expect to review a contribution | Remove it if the issue is blocked or already assigned. |

### Status Labels

Use `status:*` labels for tracker state:

| Label | Use when | Notes |
| --- | --- | --- |
| `status:needs-revalidation` | reopened or duplicated work needs fresh evidence | Do not close from historical notes alone. |
| `status:needs-review` | implementation or decision evidence needs review | Use after a PR or evidence comment is ready. |
| `status:needs-tests` | implementation exists but test coverage is incomplete | Keep the issue open with a named test target. |
| `status:needs-docs` | implementation exists but documentation is incomplete | Link the required docs path. |
| `status:blocked` | work depends on an upstream change, external data issue, or another issue/PR | Remove it as soon as the blocker clears. |
| `status:strict-dod` | explicit Definition of Done and evidence are required before closure | Use for release, deployment, and roadmap closeout work. |
| `status:architecture-decision` | implementation needs an explicit product or architecture decision | Use when scope is unclear rather than reviving template-alignment assumptions. |
| `duplicate` | another open or closed issue already tracks the same work | Close with a link to the canonical issue. |

### Area Labels

This repository uses a scoped `area:*` set. Keep that convention instead of
introducing a second, competing scope taxonomy:

- `area:core`
- `area:parser`
- `area:api`
- `area:provider`
- `area:ui`
- `area:attack`
- `area:report`
- `area:docs`
- `area:governance`
- `area:ci`
- `area:security`

Do not use public issue labels as a substitute for private vulnerability
reporting. Public issues should be rerouted to `SECURITY.md` when they contain
vulnerability disclosure detail.

### Automation Labels

If dependency automation is enabled, keep the bot-facing label set small and explicit:

| Label | Use when | Notes |
| --- | --- | --- |
| `dependencies` | a PR updates one or more project dependencies | Use for both Python package updates and workflow/action bumps. |
| `python` | a dependency or packaging change is Python-specific | Useful for pip / build / tooling updates. |
| `github-actions` | a change only affects GitHub Actions workflows or referenced actions | Useful for workflow dependency bumps and runner-related maintenance. |
| `type:frontend` plus `area:ui` | a dependency change affects the frontend npm workspace | Use for Dependabot npm updates; do not use the stale `frontend` label. |

These are not a second issue-triage taxonomy. They mainly exist so Dependabot or maintainers can label automation PRs without overloading the public issue tracker.

## Minimal Issue Triage Conventions

Use the following conventions to keep the public tracker readable:

1. Apply exactly one core type label to every issue.
2. Add `good first issue` only when the issue is small, self-contained, and includes a clear local check such as `make check`, a targeted test, or a doc-only review path.
3. Add `help wanted` only when maintainers are ready to accept outside contributions now.
4. Use at most one triage status label at a time.
5. Add at most one `area:*` label when it helps route work; do not label everything with every possible subsystem.
6. Ask for sanitized reproduction details for bugs: exact command, input format, observed output, expected output, Python version, and OS.
7. Close out-of-scope requests quickly when they would turn the project into a scanner, SaaS workflow tool, heuristic ATT&CK mapper, or unrelated security platform.
8. Do not debug private security issues in public. Redirect them to `SECURITY.md` and avoid requesting exploit details in the issue thread.

## Maintainer Notes For `good first issue`

For this repository, a `good first issue` should usually meet all of these conditions:

- touches docs, examples, packaging, or a narrow Workbench edge case
- does not require live-provider debugging against NVD, EPSS, or KEV
- does not change scoring methodology without explicit maintainer direction
- does not introduce heuristic or LLM-generated CVE-to-ATT&CK mapping behavior
- has a concrete success check a contributor can run locally

If any of those are false, use `help wanted` or keep the issue unlabeled instead.

## GitHub-Side Setup Checklist

These steps must be done on GitHub. They are not created by local files alone:

1. Set the repository visibility to `public` when the project is ready for external consumption.
2. Add the recommended repository topics in the repository "About" panel.
3. Set a concise repository description that matches the current product surface.
4. Set a social preview image that remains readable in small Reddit, Slack, and
   GitHub unfurl cards.
5. Disable Projects unless a maintained public GitHub Project board is active.
6. Enable discussions if you want a public support and workflow-help channel
   that is separate from issues.
7. Disable the wiki when versioned docs in `docs/` are the authoritative
   documentation surface.
8. Enable delete-branch-on-merge for normal PR hygiene.
9. Protect `main` against force-push and deletion at minimum. Add stricter PR or
   status-check requirements only when they match the maintainer workflow you
   actually intend to enforce.
10. Enable GitHub code security features that fit a public repository: secret
   scanning, push protection, vulnerability alerts, automated security fixes,
   and the existing CodeQL workflow.
11. Confirm GitHub is surfacing `SECURITY.md`, `CONTRIBUTING.md`,
    `CODE_OF_CONDUCT.md`, and `SUPPORT.md` in the community health surface where
    applicable, and that `README.md` links `MAINTAINERS.md`, `CHANGELOG.md`, and
    the GitHub readiness page.
12. If private vulnerability reporting is desired, enable the repository
    security/advisory setting in GitHub after the repository is public.
13. If public releases are enabled, confirm the GitHub Release object exists for
    the current tag and that the release workflow still matches the maintainer
    guidance in [docs/release_operations.md](./release_operations.md), including
    tag-only publish behavior.
14. If PyPI publishing is enabled, confirm the PyPI Trusted Publisher points at
    this repository, the `.github/workflows/release.yml` workflow, and the `pypi`
    environment, and that the hosted-index install verification job is green.
15. If TestPyPI validation is enabled, confirm the separate Trusted Publisher
    points at `.github/workflows/testpypi.yml`, the `testpypi` environment, that
    the repository variable `TEST_PYPI_PUBLISH_ENABLED` is intentional, and that
    the hosted-index install verification job is green.

## Reddit Launch Checklist

Use this checklist before sharing the repository in Reddit security,
DevSecOps, vulnerability management, or open-source communities:

1. Link to the repository root or the latest GitHub Release, not a deep docs
   page.
2. Use the recommended external-share title or another title that says
   "local-first CVE prioritization" without implying scanner, exploit, or AI
   autopatching behavior.
3. Put the install command, supported input formats, safety boundary, and demo
   screenshot in the first comment or post body.
4. Mention that sample data is synthetic and that users should not post private
   scanner exports, customer data, tokens, internal hostnames, or exploit
   payloads in public threads.
5. Link `SECURITY.md` for vulnerability reports and `SUPPORT.md` for usage
   questions.
6. Avoid broad claims such as "production certified", "detects exploitation",
   "maps every CVE to ATT&CK", or "automatically fixes vulnerabilities" unless a
   current release has explicit evidence for that exact claim.

## Recommended `main` Protection Baseline

For this repository, a practical baseline is:

- required status checks: `check` and `Analyze Python`
- strict status checks enabled so PRs must be up to date before merge
- at least one approving review for pull requests
- stale approvals dismissed on new commits
- conversation resolution required
- linear history required
- force-push and branch deletion disabled
- admin bypass retained for emergencies when there is only one maintainer

This keeps normal contributions on the PR path without deadlocking a solo maintainer during release or incident work.

## Pull Request Readiness Baseline

Treat a PR as ready for review when it:

- explains whether the change affects Workbench, Docker, docs, release, packaging, or repository automation behavior
- includes the local checks run, with `make check` for behavior changes and `make docs-check` or targeted command-help checks for docs-only changes
- keeps README, roadmap, release operations, and public examples aligned with the currently supported install and Workbench quickstart paths
- preserves the no-scanner and no-heuristic/AI CVE-to-ATT&CK scope boundaries
- calls out any GitHub-side follow-up that cannot be completed by repository files, such as topics, homepage, branch protection, or trusted-publisher settings

## Local Repo Checklist

These items stay versioned in the repository and should be reviewed together:

1. Keep `CONTRIBUTING.md` aligned with the real local quality gate and scope guardrails.
2. Keep `SECURITY.md` aligned with the actual disclosure path.
3. Keep `SUPPORT.md`, `CODE_OF_CONDUCT.md`, and `MAINTAINERS.md` aligned with
   the actual support, conduct, and ownership paths.
4. Keep issue templates aligned with the current label names.
5. Keep [docs/github-open-source-readiness.md](./github-open-source-readiness.md)
   aligned with the GitHub-facing repository surface.
6. Keep [docs/release_operations.md](./release_operations.md) aligned with the actual GitHub Release and PyPI publishing flow.
7. Revalidate README install wording and public quickstart examples whenever the supported public install path changes, especially when PyPI moves from gated to live.
8. Update this document when topics, labels, or triage conventions change.
