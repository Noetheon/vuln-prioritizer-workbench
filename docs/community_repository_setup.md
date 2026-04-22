# Community And Public Repository Setup

This document is a maintainer checklist for running `vuln-prioritizer` as a public GitHub repository. It is intentionally scoped to a security-focused CLI for prioritizing known CVEs, not a general app platform or community program.

Use it for two different jobs:

- keep the local repository documentation consistent
- configure the small set of GitHub-side settings that cannot be created from files in this repo

## What Lives Where

The split matters:

| Item | Where it is managed | Notes |
| --- | --- | --- |
| `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md` | local docs in the repo | Versioned guidance. GitHub can surface these automatically. |
| `.github/ISSUE_TEMPLATE/*.md` and `.github/ISSUE_TEMPLATE/config.yml` | local files in the repo | Versioned templates and contact links. GitHub uses them after they land on the default branch. |
| [docs/release_operations.md](./release_operations.md) | local doc in the repo | Maintainer runbook for GitHub Releases and PyPI publishing. |
| This document | local doc in the repo | Maintainer reference only. It does not create labels, topics, or repository settings by itself. |
| Repository topics | GitHub UI or API | Must be configured on GitHub. |
| Label definitions and colors | GitHub UI or API | Must be configured on GitHub. Template front matter can reference labels, but it does not create them. |
| Repository visibility and surface settings | GitHub UI or API | Public/private state, discussions, wiki, homepage, merge cleanup, and related toggles must be configured on GitHub. |
| Private vulnerability reporting or security advisories settings | GitHub repository settings | Must be configured on GitHub if the project wants GitHub-managed private reporting in addition to `SECURITY.md`. |

## Recommended Repository Topics

Start with a small topic set that accurately describes the project:

- `python`
- `cli`
- `security`
- `cve`
- `epss`
- `kev`
- `mitre-attack`
- `vulnerability-management`
- `sbom`
- `sarif`

Optional topics when they reflect the current release surface:

- `openvex`
- `cyclonedx`

Avoid adding adjacent-but-misleading topics such as `scanner`, `siem`, `edr`, or `threat-intelligence-platform`. The project is a local-first prioritization CLI for known CVEs, not a scanning engine or security platform.

## Recommended Label Taxonomy

Keep the label set small. The goal is routing and contributor clarity, not process theater.

### Core Type Labels

These should exist before opening the repo to wider contribution:

| Label | Use when | Notes |
| --- | --- | --- |
| `bug` | behavior is incorrect, regressed, or broken | Already used by the bug issue template. |
| `enhancement` | a scoped product improvement is requested | Already used by the feature request template. |
| `documentation` | the main work is docs, examples, or guidance | Good candidate for low-risk external contributions. |
| `maintenance` | dependency, CI, release, packaging, or cleanup work | Use for repo upkeep that is not user-facing behavior. |

### Community Labels

These help contributors self-select:

| Label | Use when | Notes |
| --- | --- | --- |
| `good first issue` | a newcomer can complete the work with clear file pointers and a local verification path | Do not use for provider, scoring, or ATT&CK design work unless the change is tightly bounded. |
| `help wanted` | maintainers actively want outside help and expect to review a contribution | Remove it if the issue is blocked or already assigned. |

### Minimal Triage Labels

Add only the few status labels that reduce back-and-forth:

| Label | Use when | Notes |
| --- | --- | --- |
| `needs-repro` | a bug report is missing a concrete command, input shape, or output evidence | Prefer this over long clarification threads. |
| `needs-decision` | the issue is valid, but a maintainer scope or product decision is still needed | Useful for roadmap-bound feature requests. |
| `blocked` | work depends on an upstream change, external data issue, or another issue/PR | Remove it as soon as the blocker clears. |
| `duplicate` | another open or closed issue already tracks the same work | Close with a link to the canonical issue. |

### Area Labels

This repository already uses a small `area:*` set. Keep that convention instead of introducing a second, competing scope taxonomy:

- `area:benchmarking`
- `area:workflow`
- `area:governance`
- `area:release`
- `area:docs`

Do not create a public `security` issue label for vulnerability disclosures. Public issues should be rerouted to `SECURITY.md` instead of encouraging security reports in the issue tracker.

### Automation Labels

If dependency automation is enabled, keep the bot-facing label set small and explicit:

| Label | Use when | Notes |
| --- | --- | --- |
| `dependencies` | a PR updates one or more project dependencies | Use for both Python package updates and workflow/action bumps. |
| `python` | a dependency or packaging change is Python-specific | Useful for pip / build / tooling updates. |
| `github-actions` | a change only affects GitHub Actions workflows or referenced actions | Useful for workflow dependency bumps and runner-related maintenance. |

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

- touches docs, examples, packaging, or a narrow CLI edge case
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
4. Enable discussions if you want a public support and workflow-help channel that is separate from issues.
5. Disable the wiki when versioned docs in `docs/` are the authoritative documentation surface.
6. Enable delete-branch-on-merge for normal PR hygiene.
7. Protect `main` against force-push and deletion at minimum. Add stricter PR or status-check requirements only when they match the maintainer workflow you actually intend to enforce.
8. Enable GitHub code security features that fit a public repository: secret scanning, push protection, vulnerability alerts, automated security fixes, and the existing CodeQL workflow.
9. Confirm GitHub is surfacing `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `SUPPORT.md` in the community health surface where applicable.
10. If private vulnerability reporting is desired, enable the repository security/advisory setting in GitHub after the repository is public.
11. If public releases are enabled, confirm the GitHub Release object exists for the current tag and that the release workflow still matches the maintainer guidance in [docs/release_operations.md](./release_operations.md), including tag-only publish behavior.
12. If PyPI publishing is enabled, confirm the PyPI Trusted Publisher points at this repository, the `.github/workflows/release.yml` workflow, and the `pypi` environment, and that the hosted-index install verification job is green.
13. If TestPyPI validation is enabled, confirm the separate Trusted Publisher points at `.github/workflows/testpypi.yml`, the `testpypi` environment, that the repository variable `TEST_PYPI_PUBLISH_ENABLED` is intentional, and that the hosted-index install verification job is green.

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

## Local Repo Checklist

These items stay versioned in the repository and should be reviewed together:

1. Keep `CONTRIBUTING.md` aligned with the real local quality gate and scope guardrails.
2. Keep `SECURITY.md` aligned with the actual disclosure path.
3. Keep issue templates aligned with the current label names.
4. Keep [docs/release_operations.md](./release_operations.md) aligned with the actual GitHub Release and PyPI publishing flow.
5. Revalidate README install wording and public quickstart examples whenever the supported public install path changes, especially when PyPI moves from gated to live.
6. Update this document when topics, labels, or triage conventions change.
