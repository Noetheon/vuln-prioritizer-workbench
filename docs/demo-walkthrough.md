# Demo Walkthrough

This is the presentation script for the **Online Shop Demo Workspace**. The
seed is deterministic: every reset produces the same findings, the same
timeline shape, and the same talking points. All numbers below come from the
canonical seed (`Reset demo`).

## The Story In One Sentence

> "Three months ago every scan looked uniformly catastrophic. We widened
> coverage, accepted four risks explicitly, fixed and suppressed what evidence
> allowed - and today the workbench tells us the one action that moves risk
> the most."

## Dataset Shape

| Fact | Value |
| --- | --- |
| Findings / assets | 32 findings across 21 assets |
| Priorities | 19 Critical, 2 High, 5 Medium, 6 Low |
| Statuses | 24 open, 1 in review, 1 remediating, 1 fixed, 4 accepted, 1 suppressed |
| Signals | 16 CISA KEV findings, 19 with EPSS >= 70% |
| ATT&CK | 21 findings mapped (65.6%), xz and the long tail unmapped |
| Governance | 4 waivers (3 active, 1 review due), VEX with 4 statement types |
| Analysis runs | 6 backdated seeded runs plus the current live state |

The headline CVEs are intentionally recognizable (Log4Shell, Spring4Shell,
MOVEit, Zerologon, xz, PHP-CGI) and sit next to a deliberately boring long
tail (jackson-databind, systemd, curl, openssl, setuptools, requests) so the
prioritization is visible instead of drowned in uniform noise.

## Walkthrough (Overview Page)

1. **Risk index (left).** The index is the average operational score of open
   actionable findings: **62.1**, in the moderate band. The severity strip
   below shows all four priority segments - this is a mixed backlog, not a
   wall of critical.
2. **Scenario projection (center).** Six backdated analysis runs decline from
   **94.5 to 64.5** before TODAY: coverage grew (8 -> 32 findings) while
   waivers, VEX statements, and one fix landed. Right of TODAY the simulation
   shows what the checked plan would achieve against the dashed target line.
3. **Top risk reducers (right).** The biggest lever is one upgrade:
   **log4j-core 2.14.1 across three services** (fulfillment, orders,
   payments). Toggling a reducer instantly re-simulates the projection -
   uncheck everything and the plan readout drops to zero actions.
4. **Per-asset scoring.** Open the remediation queue: the same CVE carries
   different scores per asset - Log4Shell is **100 on the internet-facing
   payment API** but **92 on the internal warehouse worker**; xz is 78 on the
   CI build host and 70 on an isolated notebook. Context is a real
   differentiator, and each finding's "Why this priority" panel lists the
   exact reason lines that add up to its score.
5. **Workflow states.** The Spring deserialization finding on the order API is
   `remediating`; the MOVEit auth-bypass on the partner portal is
   `in_review` - the backlog is being worked, not just stared at.
6. **Governance.** Risk Acceptance shows 4 scoped, time-bound waivers (one due
   for review). The suppressed MOVEit finding on the DR node and the fixed
   log4j on the ETL host demonstrate VEX-driven statuses. Evidence Center
   holds the seven generated report artifacts with checksums.

## Useful Demo Beats

- **Reset demo** reseeds everything deterministically (7 imports, ~30s).
- Unchecking reducers live during a presentation shows the simulation honestly
  saying "target not reached; check more reducers".
- The audit log records the manual workflow status changes
  (`finding.status`), the imports, and the waiver lifecycle - useful when the
  evidence story is challenged.

## Known Modeling Choices

- The KEV share (16/32) is intentionally above real-world rates: this is a
  curated incident-review workspace, not a raw scanner dump.
- Vulnerability decisions are made per CVE; the per-asset score scopes the
  context portion. Spread bonus and recommended action remain CVE-wide.
- Manual statuses are limited to open / in review / remediating. Accepted,
  suppressed, and fixed remain owned by waivers, VEX, and imports.
