# Use Cases

This page focuses on three concrete operational workflows that the current `v1.1.0` surface supports well.

## 1. Trivy + VEX + GitHub Summary

Goal:

- turn a container-security scan into a CI-friendly prioritized summary
- suppress exact-match `not_affected` VEX cases
- keep a JSON artifact plus a short Markdown summary for the GitHub run

CLI shape:

```bash
vuln-prioritizer analyze \
  --input data/input_fixtures/trivy_report.json \
  --input-format trivy-json \
  --vex-file data/input_fixtures/openvex_statements.json \
  --format json \
  --output analysis.json \
  --summary-output summary.md \
  --html-output report.html
```

Why it matters:

- developers get a short executive summary
- automation still consumes stable JSON or SARIF
- VEX reduces noise without hiding how the decision was made

## 2. CycloneDX or Dependency-Check Triage

Goal:

- prioritize SBOM and dependency findings without introducing a second opaque risk model
- compare raw CVSS-only intuition with enriched prioritization

CLI shape:

```bash
vuln-prioritizer compare \
  --input data/input_fixtures/cyclonedx_bom.json \
  --input-format cyclonedx-json \
  --format markdown \
  --output compare.md
```

Why it matters:

- dependency-heavy teams can explain why a CVE moved up or stayed flat
- SBOM inputs keep package context, paths, and fix-version hints visible

## 3. Nessus or OpenVAS + Asset Context + ATT&CK

Goal:

- move from a flat infrastructure scan to service-aware prioritization
- attach mapped assets and business services
- add optional ATT&CK context and later aggregate by asset or service

CLI shape:

```bash
vuln-prioritizer analyze \
  --input data/input_fixtures/openvas_report.xml \
  --input-format openvas-xml \
  --asset-context data/input_fixtures/example_asset_context.csv \
  --attack-source ctid-json \
  --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json \
  --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json \
  --format json \
  --output analysis.json

vuln-prioritizer rollup \
  --input analysis.json \
  --by service \
  --format markdown \
  --output rollup.md
```

Why it matters:

- remediation can be discussed at the service layer, not only at the CVE layer
- the rollup output now ranks services explicitly and surfaces per-bucket “patch these first” candidates
- ATT&CK stays an explicit context layer instead of silently changing the base score

## Media

Committed preview assets live here:

- [HTML report preview](examples/media/html-report-preview.png)
- [Workflow demo GIF](examples/media/workflow-demo.gif)
