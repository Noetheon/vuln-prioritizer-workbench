# Use Cases

This page focuses on concrete operational workflows that the current CLI surface supports well.

If you want the shortest operator-facing runbooks instead of the product-story view, start with [Operator Playbooks](playbooks.md).

All CLI examples below are repo-checkout examples that intentionally use the checked-in fixtures under `data/`. The commands themselves are part of the public CLI surface, but after `pipx install` alone you must replace those fixture paths with your own existing scan exports, SBOMs, VEX files, asset-context CSVs, and ATT&CK mapping files.

## 1. Trivy + VEX + GitHub Summary

Goal:

- turn an existing container-security scan export into a CI-friendly prioritized summary
- suppress matching `not_affected` VEX cases
- keep a JSON artifact plus a short Markdown summary for the GitHub run

CLI shape (repo checkout example):

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

CLI shape (repo checkout example):

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

- move from an existing infrastructure scan export to service-aware prioritization
- attach mapped assets and business services
- add optional ATT&CK context and later aggregate by asset or service

CLI shape (repo checkout example):

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

## 4. Provider Snapshot Replay for Release Gates

Goal:

- pin `NVD + EPSS + KEV` evidence once
- replay the same provider evidence later without refreshing live sources
- keep local smoke tests deterministic with cache-only exports

CLI shape:

```bash
vuln-prioritizer data export-provider-snapshot \
  --input cves.txt \
  --output provider-snapshot.json

vuln-prioritizer analyze \
  --input cves.txt \
  --provider-snapshot-file provider-snapshot.json \
  --locked-provider-data \
  --format json \
  --output analysis.json
```

Cache-only smoke shape:

```bash
vuln-prioritizer data export-provider-snapshot \
  --input cves.txt \
  --cache-only \
  --output provider-snapshot.json
```

Why it matters:

- release evidence can be reproduced without feed drift
- CI smokes can run without requiring network refreshes
- locked replay fails loudly if a selected provider source lacks required CVE coverage

## Media

Current static preview assets live here:

- [HTML report preview](examples/media/html-report-preview.png)
