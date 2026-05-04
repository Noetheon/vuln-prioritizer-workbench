# Presentation Evidence Pack

This folder is an index for the final Vuln Prioritizer Workbench evidence set. It does not duplicate large screenshots; it points to the canonical proof files already committed under `docs/evidence/final-demo-flow/` and `docs/evidence/vpw-design-system-foundation/`.

## What Was Built

The Workbench now presents the defensive workflow as a product flow:

`Project -> Import -> Findings -> Finding Detail -> TTP Context -> Waivers -> Evidence Center -> Evidence Bundle`

The final UI integrates the VPW design-system foundation across Reports, Imports, Projects, Assets, Providers, Waivers, and Settings. Dashboard, Findings, and Finding Detail remain visually productized and are represented in the demo flow proof.

## Workflow Routes

- Dashboard: risk operations overview and active project context.
- Projects: workspace selection and project management.
- Imports: project-aware evidence intake for scanner, SBOM, and CVE-list inputs.
- Findings: prioritized remediation queue.
- Finding Detail: human-readable `Why this priority?` decision context.
- TTP Context: defensive ATT&CK context with no-inference behavior for unmapped findings and a curated mapping proof for one demo finding.
- Waivers: risk acceptance and governance state.
- Evidence Center: report, evidence bundle, manifest, and checksum proof.

## Risk-To-Decision Proof

The primary demo flow shows the complete product story:

1. Select an active project.
2. Import vulnerability evidence.
3. Review prioritized findings.
4. Open a critical finding.
5. Explain why it has that priority.
6. Review ATT&CK/TTP context.
7. Review accepted-risk state.
8. Generate evidence output for decision support.

The authoritative flow notes are in `../final-demo-flow/demo-flow-summary.md`.

## Primary Evidence

Use `evidence-index.md` for the full list of primary screenshots and summaries. The main proof set is:

- `../final-demo-flow/*-final.png`
- `../final-demo-flow/06-ttp-context-mapped-demo.png`
- `../final-demo-flow/demo-flow-summary.md`
- `../final-demo-flow/attack-demo-mapping-summary.md`

## Design-System Proof

VPW route integration screenshots and the complete component set are under:

- `../vpw-design-system-foundation/`

## Evidence Bundle, Manifest And Checksum Proof

The final Evidence Center proof shows an Evidence ZIP bundle generated through the existing UI action, then verified with manifest and checksum state visible:

- `../final-demo-flow/09-report-or-bundle-generated-final.png`
- `../final-demo-flow/demo-flow-summary.md`

## ATT&CK Demo Mapping Proof

The default final TTP screenshot truthfully shows the defensive no-inference state for a finding without approved ATT&CK mapping. A separate curated defensive demo mapping proof shows how a reviewed local mapping appears:

- `../final-demo-flow/06-ttp-context-final.png`
- `../final-demo-flow/06-ttp-context-mapped-demo.png`
- `../final-demo-flow/attack-demo-mapping-summary.md`

The curated mapping is defensive only. It supports prioritization, exposure review, detection planning, and remediation context. It does not prove exploitation and contains no exploit steps, payloads, proof-of-concept guidance, active probing, or offensive procedure instructions.

## Limitations

- The main final demo flow still includes a no-inference TTP state for the selected finding because that local finding did not have an approved ATT&CK mapping.
- The curated ATT&CK mapping proof is intentionally limited to one reviewed demo mapping.
- Dashboard, Findings list, and Finding Detail are productized but were not fully refactored to direct VPW route components in the design-system PR.
- Vite may still report a non-blocking large chunk warning during frontend build.
