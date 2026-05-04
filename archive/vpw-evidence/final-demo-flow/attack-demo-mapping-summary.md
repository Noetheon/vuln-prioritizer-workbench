# ATT&CK Demo Mapping Proof

## Scope

This follow-up adds one local curated demo mapping fixture for the final demo flow. The mapping is defensive context only and is used to demonstrate how a reviewed mapping appears in the Finding Detail TTP Context tab.

## Mapping

- CVE: CVE-2024-4577
- Tactic: Initial Access
- Technique: T1190 Exploit Public-Facing Application
- Confidence: High
- Source shown in UI: Local curated demo mapping
- Review status: Reviewed
- Detection coverage: Needs validation
- Safety boundary: The mapping supports defensive prioritization, exposure review, detection planning and remediation context. It does not prove exploitation.

## Local Proof Run

- Project: ATTACK Demo Mapping 1777832431
- Project ID: 5463120e-7f33-4389-a094-5e2298117116
- Run ID: c8e1d418-278a-488b-ac81-574b7a3ee5a4
- Finding ID: 0b21db56-adcc-4947-8ee0-22f950eb101e
- Import source: existing Workbench import API with `attack_source=local-curated` and `attack_mapping_file=local_curated_demo_mappings.yml`

## Evidence

- Screenshot: `docs/evidence/final-demo-flow/06-ttp-context-mapped-demo.png`
- Mapping fixture: `data/attack/local_curated_demo_mappings.yml`

## Safety Notes

- No exploit steps, payloads, proof-of-concept guidance, active probing, or offensive procedure instructions were added.
- Existing no-inference behavior remains unchanged for unmapped findings.
- No generated API client files were edited.
- No backend API contracts were changed.
