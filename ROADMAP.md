# Vuln Prioritizer Workbench Roadmap

This top-level roadmap summarizes the current delivery direction. Detailed
release-line history remains in [docs/roadmap.md](docs/roadmap.md). Historical
template migration planning is preserved in
[docs/vpw_template_execution_sequence.md](docs/vpw_template_execution_sequence.md)
and [docs/full_stack_fastapi_template_migration.md](docs/full_stack_fastapi_template_migration.md);
those pages are reference material, not active acceptance evidence.

## Product Direction

`vuln-prioritizer-workbench` is a local Workbench for prioritizing known CVEs from
existing findings, scanner exports, SBOM exports, and advisory data. It enriches
those inputs with transparent CVSS, EPSS, KEV, optional defensive ATT&CK, asset,
VEX, waiver, and provider context so teams can move from technical findings to
defensible decisions.

The project does not scan systems, exploit targets, generate PoCs, perform
credential testing, actively probe networks, autopatch software, or infer
CVE-to-ATT&CK mappings with heuristics or AI.

## Current Local Product Track

The current VPW cycle is about making the local single-user Workbench coherent,
usable, and shippable as a self-hosted app. The active work should improve the
main product path first: create/open a project, import evidence, review
prioritized findings, understand the reasoning, and export reports.

1. Main workflow reliability: keep import, enrichment, findings review,
   explanation, and report generation working through the browser UI and API.
2. Single-user runtime coherence: keep login, RBAC, API tokens, user
   management, and multi-user assumptions out of the active path.
3. Architecture cleanup: keep useful domain behavior in backend services and
   remove legacy CLI/template scaffolding when it no longer supports the
   Workbench.
4. Product polish: keep route state, generated-client ownership, examples,
   docs, and tests aligned with the implemented local runtime.

## Roadmap Guardrails

- Keep ordinary local Workbench changes small and tied to the main product
  path. Formal roadmap issue grouping is only needed when the work is actually
  being managed through GitHub issues.
- Match validation to the changed surface: commands run, artifacts or
  screenshots where useful, residual risk, and follow-up links when something
  remains open.
- Treat historical template-era and removed-runtime notes as reference material,
  not automatic completion evidence for current `backend/app` work.
- Preserve the local-first posture. Public or shared deployment hardening is a
  separate future track, not a default requirement for the current product.
- Keep ATT&CK defensive and evidence-based. Do not infer mappings.

## Key References

- [Dependency and Package Policy](docs/dependency-and-package-policy.md)
- [VPW Template Execution Sequence](docs/vpw_template_execution_sequence.md) (historical)
- [Full Stack FastAPI Template Migration Plan](docs/full_stack_fastapi_template_migration.md) (historical)
- [Template Replacement Strategy](docs/architecture/template-replacement.md) (historical)
- [Workbench Threat Model](docs/workbench-threat-model.md)
- [Current Release Roadmap](docs/roadmap.md)
