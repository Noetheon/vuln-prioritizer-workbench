# vuln-prioritizer

`vuln-prioritizer` is a local-first Workbench for prioritizing known CVEs with
transparent scoring from `CVSS + EPSS + KEV`, plus optional ATT&CK,
asset-context, VEX, waiver, report, and evidence layers. New product work
starts from the FastAPI/React Workbench.

## Public Docs

Start here when reviewing the current Workbench implementation, methodology, or
submission material.

![Documentation grid preview](media/grid.png)

- [Current product state](current-product-state.md)
- [Documentation map](documentation-map.md)
- [Documentation evidence matrix](documentation-evidence-matrix.md)
- [GitHub open source readiness](github-open-source-readiness.md)
- [External user documentation guide](user_documentation.md)
- [Current product architecture](architecture.md)
- [Scoring methodology](scoring-methodology.md)
- [ATT&CK/TTP methodology](attack-ttp-methodology.md)
- [Reports and evidence](reports-and-evidence.md)
- [Demo readiness](demo-readiness.md)
- [Submission package](submission/README.md)
- [Submission evidence sheet](submission/evidence-sheet.md)
- [Reviewer checklist](submission/reviewer-checklist.md)
- [Operational use cases](use_cases.md)
- [Operator playbooks](playbooks.md)
- [Contracts](contracts.md)
- [Support matrix](support_matrix.md)

## What It Does

- accepts plain CVE lists plus scanner and SBOM JSON inputs through the Workbench
- keeps the default priority decision rule-based and explainable
- adds CTID/MITRE ATT&CK context without heuristic CVE-to-ATT&CK guesses
- renders Markdown, JSON, SARIF, static HTML, and evidence-bundle outputs where
  the active Workbench supports them
- supports local provider status and refresh workflows for reproducibility
- runs a local Workbench with API, browser UI, imports, reports, evidence
  bundles, governance context, and ATT&CK coverage views

## Quickstart

For a complete external-user path across install, Docker, Workbench demo,
architecture, scoring, providers, reports, ATT&CK, security, and known
limitations, start with the [User Documentation Guide](user_documentation.md).

Local Workbench from a repository checkout:

```bash
cp .env.example .env
docker compose -f compose.yml -f compose.override.yml up --build backend frontend worker
curl http://127.0.0.1:8000/api/v1/workbench/health
```

Open `http://127.0.0.1:5173`, create or select a project, and import
`data/sample_cves.txt`. In the provider snapshot field, enter
`demo_provider_snapshot.json` and enable locked provider data. The checked-in
snapshot source is `data/demo_provider_snapshot.json`. The current local
Workbench is single-user and does not require a login step. This path works
without live provider API keys.

The Compose path starts the current FastAPI backend, React frontend, and durable
workflow worker. The Workbench remains local-first and uses the import-format
matrix documented in [support_matrix.md](support_matrix.md) for supported
inputs.

## Documentation Structure

- Start with [current-product-state.md](current-product-state.md) when you need
  the canonical current truth for product identity, active stack, release
  posture, and historical boundaries.
- Start with [documentation-map.md](documentation-map.md) when you need to know
  which page owns a claim or whether a page is current, historical, release,
  submission, evidence, or archive material.
- Start with [documentation-evidence-matrix.md](documentation-evidence-matrix.md)
  when you need to verify whether a claim is supported by code, tests, fixtures,
  command output, archived evidence, or an external primary source.
- Start with [user_documentation.md](user_documentation.md) when you need the full external-user path.
- Start with [concept.md](concept.md) for positioning and scope.
- Use [submission/README.md](submission/README.md) for the final Applied
  Security Project submission package.
- Read [methodology.md](methodology.md) for scoring, ATT&CK, Asset Context, and VEX semantics.
- Read [architecture.md](architecture.md) for the current FastAPI/React route architecture, generated client boundary, VPW design-system role, and shared state ownership.
- Read [dependency-and-package-policy.md](dependency-and-package-policy.md) for
  backend package contents, frontend lockfile ownership, Dependabot labels, and
  dependency-audit policy.
- Read [scoring-methodology.md](scoring-methodology.md) for the rule-based CVSS, EPSS, KEV, lifecycle, provider freshness, asset-context, and waiver methodology.
- Read [attack-ttp-methodology.md](attack-ttp-methodology.md) for curated ATT&CK/TTP mapping rules, no-inference boundaries, and the current mapped demo proof.
- Read [reports-and-evidence.md](reports-and-evidence.md) for Evidence Center formats, ZIP bundle verification, canonical contract artifacts, and archive layout.
- Read [demo-readiness.md](demo-readiness.md) for the Project -> Import -> Findings -> Finding Detail -> TTP Context -> Waivers -> Evidence Center demo flow.
- Use [workbench-offline-demo.md](workbench-offline-demo.md) for the
  reproducible locked-provider demo runbook.
- Use [support_matrix.md](support_matrix.md) and [contracts.md](contracts.md) for stable consumer-facing surfaces.
- Use [architecture/index.md](architecture/index.md), [architecture/core-workbench-schema.md](architecture/core-workbench-schema.md), and [architecture/analysis-run-provider-schema.md](architecture/analysis-run-provider-schema.md) for architecture and data-model details.
- Use [asset-context-csv.md](asset-context-csv.md) for the local asset-context CSV schema, match modes, precedence, and re-score semantics.
- Use [playbooks.md](playbooks.md) when you want the shortest role-oriented path for CI scans, SBOM triage, or infrastructure scan triage.
- Use [integrations/reporting_and_ci.md](integrations/reporting_and_ci.md) for SARIF, HTML, and local workflow guidance.
- Use [workbench-threat-model.md](workbench-threat-model.md) for Workbench security boundaries, residual risk, and release readiness checks.
- Use [submission/evidence-sheet.md](submission/evidence-sheet.md) for the
  final claim-to-evidence map.
- Use [user_documentation.md#known-limitations](user_documentation.md#known-limitations) for the consolidated external-user limitations list.
- Use [roadmap.md](roadmap.md) for shipped scope and deliberate non-goals.
- Use [release_operations.md](release_operations.md) for maintainer-only release, GitHub Release recovery, and PyPI/TestPyPI operations.
- Use [github-open-source-readiness.md](github-open-source-readiness.md) for
  public GitHub entrypoints, community health files, issue/PR routing, and
  repository-setting checks.
- Use [public-production-release-evidence-ledger.md](public-production-release-evidence-ledger.md) only when explicitly working on public/shared deployment evidence. It is not part of the normal local Workbench development path or release-readiness path.
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

- a local Workbench for known CVEs, backed by shared domain services in the
  active app
- explicit about upstream sources
- local-first and demo-friendly
- conservative about ATT&CK provenance and explainability

This project is intentionally not:

- a vulnerability scanner
- a hosted SaaS product
- a broad enterprise vulnerability-management platform
- a ticketing platform
- a heuristic or AI-generated ATT&CK mapper
