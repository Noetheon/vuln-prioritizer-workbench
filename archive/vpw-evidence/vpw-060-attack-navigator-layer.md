# VPW-060 ATT&CK Navigator Layer Export Evidence

VPW-060 adds a template Workbench ATT&CK Navigator layer artifact for completed
analysis runs.

## Delivered Scope

- Added `attack-navigator` to the template report creation contract.
- Generated `attack-navigator-layer.json` through the existing report create and
  checksum-validated download flow.
- Added Navigator layer filters:
  - `all`
  - `critical-high`
  - `kev`
  - `no-coverage`
- Added technique score, comments, and metadata for findings, KEV status,
  priority, confidence, review status, source, and coverage.
- Added optional evidence bundle inclusion as `attack-navigator-layer.json` when
  persisted ATT&CK mappings exist for the run.
- Kept unmapped findings omitted instead of inferred.

## Evidence Artifacts

- Example layer JSON:
  `docs/evidence/vpw-060-attack-navigator-layer.json`
- Browser evidence:
  `docs/evidence/vpw-060-attack-navigator-layer.png`
- Report API tests:
  `backend/tests/api/test_template_reports_api.py::test_vpw060_attack_navigator_report_create_downloads_filtered_layer`
- Evidence bundle test:
  `backend/tests/api/test_template_reports_api.py::test_vpw060_evidence_bundle_includes_attack_navigator_layer_when_mapped`
- Snapshot test:
  `backend/tests/api/test_template_reports_api.py::test_vpw060_attack_navigator_layer_snapshot_is_stable`

## Safety Notes

The layer is defensive context for prioritization and coverage review. It is
built only from persisted Workbench ATT&CK mapping context and does not generate
new CVE-to-technique mappings, exploit steps, payloads, scanners, or active
probing behavior.

`no-coverage` is intentionally a placeholder filter until the later detection
coverage model exists; exported techniques are marked as `not assessed`.
