# Vuln Prioritizer Workbench Roadmap

This top-level roadmap summarizes the current delivery direction. Detailed
release-line history remains in [docs/roadmap.md](docs/roadmap.md). The active
template-first execution plan is tracked in
[docs/vpw_template_execution_sequence.md](docs/vpw_template_execution_sequence.md)
and [docs/full_stack_fastapi_template_migration.md](docs/full_stack_fastapi_template_migration.md).

## Product Direction

`vuln-prioritizer` is a CLI and local Workbench for prioritizing known CVEs from
existing findings, scanner exports, SBOM exports, and advisory data. It enriches
those inputs with transparent CVSS, EPSS, KEV, optional defensive ATT&CK, asset,
VEX, waiver, and provider context so teams can move from technical findings to
defensible decisions.

The project does not scan systems, exploit targets, generate PoCs, perform
credential testing, actively probe networks, autopatch software, or infer
CVE-to-ATT&CK mappings with heuristics or AI.

## Current Execution Track

The current VPW cycle rebuilds the Workbench on the official
`fastapi/full-stack-fastapi-template` shape without discarding the existing
CLI/core domain value.

1. Baseline and governance: prove the official template baseline, product
   identity, auth smoke, governance docs, issue templates, milestones, and
   strict evidence flow.
2. Backend domain foundation: replace template demo Items with Workbench
   Projects, Findings, Assets, Components, Vulnerabilities, Analysis Runs,
   Provider Snapshots, and SQLModel/Alembic persistence.
3. Core package extraction: keep parser, provider, scoring, reporting, ATT&CK,
   VEX, and governance logic framework-neutral so the template backend can call
   it through service boundaries.
4. Import MVP: persist imported scanner/SBOM/advisory data as findings and
   occurrences with provenance.
5. Enrichment and prioritization: attach provider context, risk reasons,
   operational ranking, waivers, and explanations.
6. React Workbench workflow: replace demo frontend pages with dashboard,
   projects, imports, findings, detail, reports, providers, settings, and
   browser-tested user flows.
7. Evidence, reporting, ATT&CK, asset, VEX, governance, deployment, release, and
   integration hardening: land each capability with tests and evidence before
   closure.

## Roadmap Guardrails

- Keep one roadmap issue per PR unless a dependency group is explicitly stated.
- Close issues only after fresh evidence is posted: changed scope, commands run,
  artifacts, residual risk, and follow-up links.
- Treat the old FastAPI/Jinja2/SQLAlchemy Workbench as reference material, not
  automatic completion evidence for template React/JWT/SQLModel work.
- Preserve the local-first posture until public/shared deployment hardening is
  explicitly implemented and documented.
- Keep ATT&CK defensive and evidence-based. Do not infer mappings.

## Key References

- [VPW Template Execution Sequence](docs/vpw_template_execution_sequence.md)
- [Full Stack FastAPI Template Migration Plan](docs/full_stack_fastapi_template_migration.md)
- [Template Replacement Strategy](docs/architecture/template-replacement.md)
- [Workbench Threat Model](docs/workbench-threat-model.md)
- [Current Release Roadmap](docs/roadmap.md)
