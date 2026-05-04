# vuln-prioritizer

`vuln-prioritizer` is a local-first CLI and self-hosted Workbench for prioritizing known CVEs with transparent scoring from `CVSS + EPSS + KEV`, plus optional ATT&CK, asset-context, and VEX-aware explanation layers.

## Public Docs Slice

The site includes the `v1.1.0` release notes, Workbench milestone evidence, and committed media preview assets.

![Documentation grid preview](media/grid.png)

- [Release notes: v1.1.0](releases/v1.1.0.md)
- [Release notes: Workbench v1.0.0](releases/workbench-v1.0.0.md)
- [Workbench v1.0 release checklist](workbench-v1-release-checklist.md)
- [External user documentation guide](user_documentation.md)
- [Current product architecture](architecture.md)
- [Scoring methodology](scoring-methodology.md)
- [ATT&CK/TTP methodology](attack-ttp-methodology.md)
- [Reports and evidence](reports-and-evidence.md)
- [Demo readiness](demo-readiness.md)
- [Example HTML report](examples/example_report.html)
- [Template report demo artifacts](examples/vpw-054-template-technical-report.md)
- [Operational use cases](use_cases.md)
- [Operator playbooks](playbooks.md)

## What It Does

- accepts plain CVE lists plus scanner and SBOM JSON inputs
- keeps the default priority decision rule-based and explainable
- adds CTID/MITRE ATT&CK context without heuristic CVE-to-ATT&CK guesses
- renders terminal, Markdown, JSON, SARIF, and static HTML outputs
- supports local cache inspection and refresh workflows for reproducibility
- runs a local Workbench with API, browser UI, SQLite-backed imports, reports, evidence bundles, governance context, and ATT&CK coverage views

## Quickstart

For a complete external-user path across install, Docker, Workbench demo,
architecture, scoring, providers, reports, ATT&CK, security, and known
limitations, start with the [User Documentation Guide](user_documentation.md).

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

Workbench v1.0 from a repository checkout:

```bash
cp .env.example .env
docker compose -f compose.yml -f compose.override.yml up --build backend frontend
curl http://127.0.0.1:8000/api/v1/workbench/status
```

Open `http://127.0.0.1:5173`, sign in with the local `.env.example` defaults,
create a project, and import `data/sample_cves.txt` with
`demo_provider_snapshot.json` plus locked provider data enabled. This path works
without live provider API keys.

During the FastAPI template migration, Compose starts the template backend shell
and React frontend. The legacy web/API Workbench remains local-first and now
uses the same import-format matrix documented in [support_matrix.md](support_matrix.md)
for single-upload and multi-upload flows.

## Documentation Structure

- Start with [user_documentation.md](user_documentation.md) when you need the full external-user path.
- Start with [concept.md](concept.md) for positioning and scope.
- Read [methodology.md](methodology.md) for scoring, ATT&CK, Asset Context, and VEX semantics.
- Read [architecture.md](architecture.md) for the current FastAPI/React route architecture, generated client boundary, VPW design-system role, and shared state ownership.
- Read [scoring-methodology.md](scoring-methodology.md) for the rule-based CVSS, EPSS, KEV, lifecycle, provider freshness, asset-context, and waiver methodology.
- Read [attack-ttp-methodology.md](attack-ttp-methodology.md) for curated ATT&CK/TTP mapping rules, no-inference boundaries, and the current mapped demo proof.
- Read [reports-and-evidence.md](reports-and-evidence.md) for Evidence Center formats, ZIP bundle verification, canonical contract artifacts, and archive layout.
- Read [demo-readiness.md](demo-readiness.md) for the Project -> Import -> Findings -> Finding Detail -> TTP Context -> Waivers -> Evidence Center demo flow.
- Use [support_matrix.md](support_matrix.md) and [contracts.md](contracts.md) for stable consumer-facing surfaces.
- Use [architecture/index.md](architecture/index.md), [architecture/core-workbench-schema.md](architecture/core-workbench-schema.md), and [architecture/analysis-run-provider-schema.md](architecture/analysis-run-provider-schema.md) for architecture and data-model details.
- Use [asset-context-csv.md](asset-context-csv.md) for the local asset-context CSV schema, match modes, precedence, and re-score semantics.
- Use [playbooks.md](playbooks.md) when you want the shortest role-oriented path for CI scans, SBOM triage, or infrastructure scan triage.
- Use [integrations/reporting_and_ci.md](integrations/reporting_and_ci.md) for SARIF, GitHub Action, HTML, and local workflow guidance.
- Use [workbench-threat-model.md](workbench-threat-model.md) for Workbench security boundaries, residual risk, and release readiness checks.
- Use [workbench-offline-demo.md](workbench-offline-demo.md) for the locked-provider Workbench demo and v1.0 release evidence path.
- Use [user_documentation.md#known-limitations](user_documentation.md#known-limitations) for the consolidated external-user limitations list.
- Use [roadmap.md](roadmap.md) for shipped scope and deliberate non-goals.
- Use [release_operations.md](release_operations.md) for maintainer-only release, GitHub Release recovery, and PyPI/TestPyPI operations.
- Use [community_repository_setup.md](community_repository_setup.md) for maintainer-facing public repo topics, labels, and triage defaults.
- Use [releases/v1.1.0.md](releases/v1.1.0.md) for the current package release.

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

- a CLI and local Workbench for known CVEs
- explicit about upstream sources
- local-first and demo-friendly
- conservative about ATT&CK provenance and explainability

This project is intentionally not:

- a vulnerability scanner
- a hosted SaaS product
- a broad enterprise vulnerability-management platform
- a ticketing platform
- a heuristic or AI-generated ATT&CK mapper
