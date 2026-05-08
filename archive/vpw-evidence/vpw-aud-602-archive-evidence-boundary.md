# VPW-AUD-602 Archive And Evidence Boundary Evidence

Issue: VPW-AUD-602
Category: Repo Hygiene
Date: 2026-05-08

## Boundary Decision

The repo now distinguishes four evidence owners:

- `docs/evidence/`: backend/API contract owners; only small fixtures referenced
  by schemas or regression tests.
- `archive/vpw-evidence/`: release and roadmap maintainers; public-safe
  long-lived VPW evidence, scorecards, screenshots, demo summaries, and issue
  closeout artifacts.
- CI artifacts: release owner for the exact workflow run; raw command output,
  package files, Docker logs, Playwright reports, and release-readiness bundles.
- Historical screenshots: demo or submission owner; stored under named archive
  directories and linked instead of duplicated.

## Evidence Growth Rule

New VPW-AUD evidence should use a small tracked Markdown summary under
`archive/vpw-evidence/` when it must survive the PR. Raw CI output should stay
linked from the PR, issue, release, or scorecard comment for the exact run.

Do not place screenshots, raw logs, demo bundles, or broad historical issue
proof under `docs/evidence/`.

## Safety Rule

Evidence must not include secrets, tokens, cookies, customer data, private
absolute paths, or raw ignored-artifact inventories.
