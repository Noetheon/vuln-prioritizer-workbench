# vuln-prioritizer

`vuln-prioritizer` is a local-first CLI for prioritizing known CVEs with transparent scoring from `CVSS + EPSS + KEV`, plus optional ATT&CK, asset-context, and VEX-aware explanation layers.

## Public Docs Slice

The site now includes the `v1.1.0` public-polish release notes and a committed media preview asset.

![Documentation grid preview](media/grid.png)

- [Release notes: v1.1.0](releases/v1.1.0.md)
- [Example HTML report](examples/example_report.html)
- [Operational use cases](use_cases.md)

## What It Does

- accepts plain CVE lists plus scanner and SBOM JSON inputs
- keeps the default priority decision rule-based and explainable
- adds CTID/MITRE ATT&CK context without heuristic CVE-to-ATT&CK guesses
- renders terminal, Markdown, JSON, SARIF, and static HTML outputs
- supports local cache inspection and refresh workflows for reproducibility

## Quickstart

Baseline analysis:

```bash
vuln-prioritizer analyze --input data/sample_cves.txt
```

Scanner-native analysis:

```bash
vuln-prioritizer analyze \
  --input data/input_fixtures/trivy_report.json \
  --input-format trivy-json \
  --format json \
  --output analysis.json
```

ATT&CK-aware analysis:

```bash
vuln-prioritizer analyze \
  --input data/sample_cves_mixed.txt \
  --format markdown \
  --output docs/example_attack_report.md \
  --attack-source ctid-json \
  --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json \
  --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json
```

The documented default ATT&CK workflow is `ctid-json`. The older `local-csv` mode remains available only as a compatibility fallback.

## Documentation Structure

- Start with [concept.md](concept.md) for positioning and scope.
- Read [methodology.md](methodology.md) for scoring, ATT&CK, Asset Context, and VEX semantics.
- Use [support_matrix.md](support_matrix.md) and [contracts.md](contracts.md) for stable consumer-facing surfaces.
- Use [integrations/reporting_and_ci.md](integrations/reporting_and_ci.md) for SARIF, GitHub Action, HTML, and local workflow guidance.
- Use [roadmap.md](roadmap.md) for shipped scope and deliberate non-goals.
- Use [community_repository_setup.md](community_repository_setup.md) for maintainer-facing public repo topics, labels, and triage defaults.
- Use [releases/v1.1.0.md](releases/v1.1.0.md) for the current public-polish release slice.

## Local Docs Preview

Build the static site:

```bash
make docs-check
```

Serve it locally:

```bash
make docs-serve
```

## Current Positioning

This project is intentionally:

- a CLI for known CVEs
- explicit about upstream sources
- local-first and demo-friendly
- conservative about ATT&CK provenance and explainability

This project is intentionally not:

- a vulnerability scanner
- a web dashboard
- a ticketing platform
- a heuristic or AI-generated ATT&CK mapper
