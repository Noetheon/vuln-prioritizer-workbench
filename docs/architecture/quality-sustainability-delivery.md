# Sustainable quality delivery

Status: implemented; local validation recorded below. Hosted activation is verified
through the PR checks and the live GitHub protection/health audit, not this static file.

This follow-up makes the [testing strategy](../testing-strategy.md) enforceable
over time, building on the locally verified test work and main including PR #699.

| Requirement | Acceptance |
| --- | --- |
| Required admission | Selected contracts produce fresh evidence; missing/failed/skipped results fail admission. Main requires the gate without weakening existing protections. |
| Policy review | Source-bound reasons cover policy/budget/exemption changes, removed tests and new critical entry points. Future PRs use the base-branch checker. |
| Regression discipline | PR/bug templates and guidance require independent expectations, red/green reproduction or a bounded exception, owner and repair deadline. |
| Exploration | Scheduled/manual seeds vary by execution and are retained for replay; PRs remain deterministic. |
| Trends | Compact metrics survive 90 days; comparability, calibration, scope reduction, budget proximity and sustained deterioration have negative tests. |
| Monitoring | Daily read-only checks detect stale/failed/disabled campaigns; an independent Codex heartbeat also checks protection drift. |
| Release | Candidate builds depend on the reusable quality workflow for their own commit; existing release checks remain. |

## Verification record

- Existing protection inspected: five required checks, strict updates and enforced
  administrators; no required human approval. This rollout adds machine admission
  and does not invent an independent human reviewer.
- Implementation is isolated in the existing managed worktree.
- Focused admission/policy/monitoring validation: 53 tests passed. Temporary
  Git fixture creation was removed so host-specific Git hooks cannot change the
  policy unit-test result; the actual current-tree Git comparison is also checked.
- Existing package/tooling negative contracts: 40 tests passed.
- Real recovery execution through the new runner: 22 tests passed and a fresh
  successful receipt was verified.
- Native actionlint, action pins, formatting/lint, pre-commit, docs and project
  guidance checks pass. Source-bound adoption reasoning covers the affected files.
- Hosted checks and branch protection are authoritative for activation. See the
  [delivery PR](https://github.com/Noetheon/vuln-prioritizer-workbench/pulls?q=is%3Apr+head%3Acodex%2Ftest-quality-strategy)
  and [quality runs](https://github.com/Noetheon/vuln-prioritizer-workbench/actions/workflows/test-quality.yml).

These are separate outcomes. No release or package publication is part of this rollout.
