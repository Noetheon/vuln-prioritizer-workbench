# vuln-prioritizer

`vuln-prioritizer` is a local-first CLI for prioritizing known CVEs with transparent scoring from `CVSS + EPSS + KEV`, plus optional ATT&CK, asset-context, and VEX-aware explanation layers.

## Public Docs Slice

The site now includes the `v1.1.0` public-polish release notes and a committed media preview asset.

![Documentation grid preview](media/grid.png)

- [Release notes: v1.1.0](releases/v1.1.0.md)
- [Example HTML report](examples/example_report.html)
- [Operational use cases](use_cases.md)
- [Operator playbooks](playbooks.md)

## What It Does

- accepts plain CVE lists plus scanner and SBOM JSON inputs
- keeps the default priority decision rule-based and explainable
- adds CTID/MITRE ATT&CK context without heuristic CVE-to-ATT&CK guesses
- renders terminal, Markdown, JSON, SARIF, and static HTML outputs
- supports local cache inspection and refresh workflows for reproducibility

## Quickstart

- Works after a public install: examples that use files you create or already have locally, such as `cves.txt`, `trivy-results.json`, `analysis.json`, or `report.html`.
- Requires local ATT&CK data files: examples that use `--attack-mapping-file` and `--attack-technique-metadata-file`.
- Repo checkout only: examples that use `data/...` or `make ...` in this repository.

Baseline analysis:

```bash
printf 'CVE-2021-44228\nCVE-2024-3094\n' > cves.txt
vuln-prioritizer analyze --input cves.txt
```

Scanner-native analysis:

```bash
vuln-prioritizer analyze \
  --input trivy-results.json \
  --input-format trivy-json \
  --format json \
  --output analysis.json
```

ATT&CK-aware analysis with your own local mapping files:

```bash
vuln-prioritizer analyze \
  --input cves.txt \
  --format markdown \
  --output attack-report.md \
  --attack-source ctid-json \
  --attack-mapping-file ./attack-mapping.json \
  --attack-technique-metadata-file ./attack-techniques.json
```

The documented default ATT&CK workflow is `ctid-json`. The older `local-csv` mode remains available only as a compatibility fallback.
If you are working from a repository checkout, the checked-in demo ATT&CK files live under `data/attack/`; they are not installed by `pipx`.

## Documentation Structure

- Start with [concept.md](concept.md) for positioning and scope.
- Read [methodology.md](methodology.md) for scoring, ATT&CK, Asset Context, and VEX semantics.
- Use [support_matrix.md](support_matrix.md) and [contracts.md](contracts.md) for stable consumer-facing surfaces.
- Use [playbooks.md](playbooks.md) when you want the shortest role-oriented path for CI scans, SBOM triage, or infrastructure scan triage.
- Use [integrations/reporting_and_ci.md](integrations/reporting_and_ci.md) for SARIF, GitHub Action, HTML, and local workflow guidance.
- Use [roadmap.md](roadmap.md) for shipped scope and deliberate non-goals.
- Use [release_operations.md](release_operations.md) for maintainer-only release, GitHub Release recovery, and PyPI/TestPyPI operations.
- Use [community_repository_setup.md](community_repository_setup.md) for maintainer-facing public repo topics, labels, and triage defaults.
- Use [releases/v1.1.0.md](releases/v1.1.0.md) for the current public-polish release slice.

## Local Docs Preview (Repo Checkout Only)

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
