# Final Demo Flow Summary

Date: 2026-05-03

Base URL: `http://127.0.0.1:5175`

Status: historical local demo evidence. This file records what was visible in a
specific local Workbench run; it is not current release certification and does
not replace active tests or fresh provider checks.

## Workflow Proof

- Active project used for the final proof: `VPW Governance Project moouh3af`.
- Dashboard, Projects, Imports, Findings, Finding Detail, TTP Context, Waivers, and Evidence Center were verified in the running app.
- Imports was captured after selecting the active project, so the final screenshot shows project context.
- Prioritized Findings showed critical findings for the active project.
- Critical finding opened: `CVE-2024-4577` at `/findings/1b024e76-78ef-48ac-a298-85e4bd38df4d`.
- Finding Detail showed `Why this priority?` with human-readable decision text and no visible `priority.*` reason keys.
- Waivers showed the accepted-risk register and review state.
- Evidence Center generated an Evidence ZIP bundle through the existing UI action and displayed bundle, manifest, and checksum state.

## TTP Context

No persisted local finding currently has `attack_mapped=true` or approved ATT&CK technique rows. The final TTP screenshot therefore shows the defensive no-inference state: no approved ATT&CK mapping is stored, and Workbench does not infer tactics or techniques for unmapped CVEs.

This is truthful product behavior, not a completed mapped TTP proof.

## Evidence Generation

- Existing UI action used: `Build Evidence Bundle`.
- Existing verification action was available and clicked.
- Final Evidence Center state showed Evidence ZIP, manifest, and checksum text.
- No backend source, generated API client, or API contract files were edited for this proof.

## Screenshot Retention

The original final-flow screenshots were pruned from `main` during the
2026-05-25 archive trim. This summary remains as a compact historical record of
the reviewed route sequence. Current UI proof should come from fresh Playwright
screenshots, current docs media, or CI artifacts for the run being evaluated.
