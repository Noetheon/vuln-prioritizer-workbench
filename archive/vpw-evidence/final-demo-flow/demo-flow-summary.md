# Final Demo Flow Summary

Date: 2026-05-03

Base URL: `http://127.0.0.1:5175`

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

## Final Screenshots

- `01-dashboard-final.png`
- `02-projects-final.png`
- `03-imports-final.png`
- `04-findings-final.png`
- `05-finding-detail-final.png`
- `06-ttp-context-final.png`
- `07-waivers-final.png`
- `08-evidence-center-final.png`
- `09-report-or-bundle-generated-final.png`

## Previous Screenshots Retained

- `01-dashboard.png`
- `02-projects.png`
- `03-imports.png`
- `04-findings.png`
- `05-finding-detail.png`
- `06-ttp-context.png`
- `07-waivers.png`
- `08-evidence-center.png`
- `09-report-generated.png`
