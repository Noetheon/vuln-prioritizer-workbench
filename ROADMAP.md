# Vuln Prioritizer Workbench Roadmap

This top-level roadmap summarizes the current delivery direction. Detailed
release-line history remains in [docs/roadmap.md](docs/roadmap.md). Historical
template migration planning is preserved in
[docs/vpw_template_execution_sequence.md](docs/vpw_template_execution_sequence.md)
and [docs/full_stack_fastapi_template_migration.md](docs/full_stack_fastapi_template_migration.md);
those pages are reference material, not active acceptance evidence.

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

The current VPW cycle hardens the implemented `backend/app` Workbench, retained
CLI/core package, React frontend, generated-client boundary, docs, packaging,
and release gates for public release-readiness review.

1. Security/auth/deployment baseline: document and verify the implemented
   session, token, upload/report, CSP/routing, health/readiness, dependency, and
   public deployment controls.
2. Migration/package/docs coherence: keep issue templates, package boundaries,
   generated-client ownership, archive boundaries, and current-state docs
   aligned with the implemented runtime.
3. Public release evidence: collect package contents, source-tag
   install smoke, docs build, client drift, evidence bundle verification, Docker
   smoke, and residual-risk decisions in the release evidence ledger.
4. Final readiness certification: run the final quality gate and close the
   release-readiness scorecard only when every category has current evidence and
   no unresolved high-priority blocker.

## Roadmap Guardrails

- Keep one roadmap issue per PR unless a dependency group is explicitly stated.
- Close issues only after fresh evidence is posted: changed scope, commands run,
  artifacts, residual risk, and follow-up links.
- Treat historical template-era and removed-runtime notes as reference material,
  not automatic completion evidence for current `backend/app` work.
- Preserve the local-first posture until public deployment hardening and fresh
  release evidence explicitly support a stronger claim.
- Keep ATT&CK defensive and evidence-based. Do not infer mappings.

## Key References

- [Public-Production Release Evidence Ledger](docs/public-production-release-evidence-ledger.md)
- [Dependency and Package Policy](docs/dependency-and-package-policy.md)
- [VPW Template Execution Sequence](docs/vpw_template_execution_sequence.md) (historical)
- [Full Stack FastAPI Template Migration Plan](docs/full_stack_fastapi_template_migration.md) (historical)
- [Template Replacement Strategy](docs/architecture/template-replacement.md)
- [Workbench Threat Model](docs/workbench-threat-model.md)
- [Current Release Roadmap](docs/roadmap.md)
