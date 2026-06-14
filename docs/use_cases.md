# Use Cases

This page focuses on concrete local Workbench workflows. The old CLI examples
have been retired; new work should use the browser Workbench or the local
FastAPI API.

## 1. Container Scan Triage

Goal:

- import an existing Trivy or Grype JSON export
- preserve package, image, path, and fix-version context
- review CVSS, EPSS, KEV, VEX, waiver, and asset context in one queue
- export Markdown, HTML, JSON, CSV, SARIF, or an evidence bundle

Workbench path:

1. Open the local Workbench.
2. Select or create a project.
3. Import the scanner export with `input_type=trivy-json` or
   `input_type=grype-json`.
4. Add optional VEX and asset-context files during import.
5. Review Findings and create reports from the Reports view.

Why it matters:

- developers see a short prioritized queue instead of raw scanner severity alone
- VEX reduces noise without hiding how the decision was made
- report artifacts remain tied to the analysis run

## 2. SBOM and Dependency Triage

Goal:

- prioritize [CycloneDX](cyclonedx-json-import.md),
  [SPDX](spdx-json-import.md), or
  [Dependency-Check](dependency-check-json-import.md) vulnerability exports
- keep package names, versions, paths, and source severity visible
- route remediation by owner, service, or asset when context is available

Workbench path:

1. Import the SBOM or dependency export with the matching input type.
2. Add asset context when ownership matters.
3. Use Findings filters for priority, KEV, VEX, waiver, and ATT&CK context.
4. Use Reports for durable JSON, CSV, Markdown, HTML, SARIF, or evidence ZIP
   artifacts.

Why it matters:

- dependency-heavy teams can explain why a CVE moved up or stayed flat
- package context stays visible next to prioritization signals
- governance rollups support service-level remediation planning

## 3. Infrastructure Scan Triage

Goal:

- import Nessus or OpenVAS XML exports without running a scanner
- attach asset, owner, service, environment, exposure, and criticality context
- use optional reviewed ATT&CK mappings as defensive context

Workbench path:

1. Import the XML export with [`input_type=nessus-xml`](nessus-xml-import.md)
   or [`input_type=openvas-xml`](openvas-xml-import.md).
2. Upload asset context when available.
3. Select reviewed ATT&CK context only when you have explicit local mapping data.
4. Review Findings, Assets, TTP Context, and Reports.

Why it matters:

- remediation can be discussed at the asset and service layer
- ATT&CK remains explicit context instead of silently changing the base score
- XML parsing stays local and bounded

## 4. Deterministic Review With Provider Snapshots

Goal:

- pin NVD, EPSS, and KEV evidence for repeatable demos or review runs
- avoid feed drift while validating UI, reports, and evidence bundles

Workbench path:

1. Store or generate a provider snapshot JSON file.
2. Import findings with the provider snapshot selected.
3. Enable locked provider data when the run must fail on missing snapshot
   coverage.
4. Export the report and evidence bundle from the completed run.

Why it matters:

- evidence can be reproduced without live feed drift
- demos and tests do not require provider API keys
- missing coverage fails visibly instead of silently falling back
