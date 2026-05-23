# Workbench Reporting and CI Integration

The old CLI and root composite GitHub Action have been removed from the active
product surface. CI systems should keep producing scanner/SBOM artifacts, then
hand those artifacts to the local Workbench or its FastAPI API for
prioritization and report generation.

## Supported Integration Shape

1. CI produces an existing evidence file, such as Trivy JSON, Grype JSON,
   CycloneDX JSON, SPDX JSON, Dependency-Check JSON, Nessus XML, or OpenVAS XML.
2. A local Workbench operator or automation imports that file into a Workbench
   project.
3. The completed run generates report artifacts from the Workbench Reports
   surface.
4. Optional evidence bundles are verified before external sharing.

## Import API

The local API endpoint is:

```text
POST /api/v1/projects/{project_id}/imports
```

Required multipart fields:

- `input_type`
- `file`

Optional multipart fields:

- `asset_context_file`
- `vex_file`
- `provider_snapshot_file`
- `locked_provider_data`
- `attack_source`
- `attack_mapping_file`
- `attack_technique_metadata_file`

Example:

```bash
curl -F input_type=trivy-json \
  -F file=@trivy-results.json \
  -F vex_file=@openvex.json \
  http://127.0.0.1:8000/api/v1/projects/<project-id>/imports
```

## Report API

Reports are created from completed runs:

```text
POST /api/v1/runs/{run_id}/reports
```

Supported report formats:

- `markdown`
- `html`
- `json`
- `csv`
- `sarif`
- `zip`
- `attack-navigator`

Downloads use:

```text
GET /api/v1/reports/{report_id}/download
```

Evidence ZIP verification uses:

```text
POST /api/v1/reports/{report_id}/verify
```

## SARIF

Workbench SARIF exports are SARIF 2.1.0 and keep stable CVE-addressable rules
and fingerprints. Use SARIF when GitHub Code Scanning or another SARIF consumer
is the target.

## Evidence Bundles

Use evidence ZIP reports when a review board, release gate, or handoff needs an
offline artifact set. Verify the bundle before sharing it outside the local
workspace.

## Removed Integration Paths

The following are no longer supported:

- root `action.yml` composite Action
- CLI modes such as `analyze`, `report html`, `report workbench`, or
  `report evidence-bundle`
- install-safe CLI smoke tests
- CLI parity artifacts

Historical release notes and archived evidence may still mention those paths,
but new integrations should use the Workbench API.
