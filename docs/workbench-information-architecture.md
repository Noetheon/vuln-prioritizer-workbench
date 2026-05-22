# Workbench Information Architecture

Status: canonical IA documentation for the Workbench frontend. This document defines route purpose, page archetypes, and information hierarchy. It does not migrate route code.

The Workbench is a local-first, single-user vulnerability prioritization and evidence workbench for already-known CVEs from supplied evidence. Its IA must keep users oriented around supplied evidence, provider trust, prioritization, decision rationale, remediation/risk acceptance, and evidence/report export.

Use this document with:

- `docs/workbench-ui-audit.md`
- `docs/workbench-ui-system.md`
- `docs/workbench-ui-migration-plan.md`
- `frontend/src/AppRouter.tsx`
- `frontend/src/lib/app-route-config.ts`
- `frontend/src/lib/workbench-navigation.ts`

## 1. Product Workflow

Canonical workflow:

```text
Evidence in
  -> provider trust
  -> signal review
  -> prioritized findings
  -> decision rationale
  -> remediation/acceptance
  -> report/evidence export
```

What each step means:

| Workflow step | Meaning in the Workbench | Primary surfaces |
| --- | --- | --- |
| Evidence in | User supplies local evidence files or existing local records and reviews import/normalization results. | `/imports`, `/imports/new`, `/imports/formats`, `/imports/runs/:runId` |
| Provider trust | User checks whether local provider datasets and imported source facts are fresh, complete, and trustworthy. | `/providers`, `/settings`, provider sections inside detail pages |
| Signal review | User reviews evidence-backed prioritization signals such as KEV, EPSS, SSVC, VEX, exposure, freshness, and source quality. | `/`, `/findings`, `/findings/:findingId`, `/assets`, `/providers` |
| Prioritized findings | User works from the queue of known findings and chooses what deserves attention first. | `/findings`, `/findings/:findingId` |
| Decision rationale | User records or inspects why remediation or acceptance is appropriate. | `/findings/:findingId`, `/waivers`, `/reports` |
| Remediation/acceptance | User tracks remediation state or risk acceptance decisions. | `/findings/:findingId`, `/waivers`, `/projects` |
| Report/evidence export | User generates or inspects evidence-backed reports, manifests, history, and artifacts. | `/reports`, `/imports/runs/:runId`, `/findings/:findingId` |

IA rule: every route should make its position in this workflow clear through page metadata, context bar facts, primary content, and evidence/provenance rows.

## 2. Page Archetypes

| Archetype | Use for | Primary layout | Primary component defaults |
| --- | --- | --- | --- |
| Overview | Cross-surface operational summary and next action. | Shell page header, context bar, metric strip, focused summary sections, optional right rail. | `ContextBar`, `MetricStrip`, `PageSection`, `DetailRail`, `Callout`. |
| Queue | Prioritized work list. | Shell page header, optional context bar, metric strip, filter bar, data table frame, detail drawer. | `FilterBar`, `DataTableFrame`, `StatusBadge`, `SignalBadge`, `DetailDrawer`. |
| Registry | Inventory of local projects, providers, imports, assets, waivers, formats, or sources. | Shell page header, context bar or metric strip, filter bar, data table frame, optional drawer. | `DataTableFrame`, `FilterBar`, `DefinitionList`, `StatusBadge`, `EmptyState`. |
| Detail record | One finding, import run, asset, or other object. | Shell page header, context bar, decision summary when relevant, tabs/sections, evidence rows, definition lists, optional right rail. | `ContextBar`, `DecisionSummary`, `EvidenceRow`, `DefinitionList`, `DetailRail`, `Callout`. |
| Evidence/report | Artifacts, manifests, decision records, quality facts, and export history. | Shell page header, run/report context bar, metric strip, tabs/sections, evidence rows, artifact list/table, optional drawer. | `ContextBar`, `EvidenceRow`, `DecisionSummary`, `DataTableFrame`, `DetailDrawer`. |
| Settings/form | Local configuration, import form, diagnostics, and setup tasks. | Shell page header, form sections, status rows, definition lists, validation callouts, optional right rail. | `PageSection`, `DefinitionList`, `Callout`, `DetailRail`, `EmptyState`. |

## 3. Route Mapping

Active routes are defined in `frontend/src/AppRouter.tsx`.

| Route | Route files | Archetype | Canonical role |
| --- | --- | --- | --- |
| `/` | `frontend/src/workbench/routes/DashboardRoute.tsx`, `frontend/src/components/dashboard/RiskOperationsDashboard.tsx` | Overview | Show current operational risk posture and next action. |
| `/findings` | `frontend/src/workbench/routes/FindingsRoute.tsx`, `frontend/src/components/findings/RemediationQueue.tsx` | Queue | Prioritize and triage known findings. |
| `/findings/:findingId` | `frontend/src/workbench/routes/FindingDetailRoute.tsx`, `frontend/src/components/finding-detail/FindingDetailRoute.tsx` | Detail record | Inspect one finding, evidence, decision rationale, and remediation/acceptance state. |
| `/imports` | `frontend/src/workbench/routes/ImportsRoute.tsx`, `frontend/src/components/imports/ImportsWorkbench.tsx` | Registry | Review import runs and start supplied-evidence ingestion. |
| `/imports/new` | `frontend/src/workbench/routes/ImportsRoute.tsx`, `frontend/src/components/imports/NewImportRoute.tsx` | Settings/form | Configure and validate a new supplied-evidence import. |
| `/imports/formats` | `frontend/src/workbench/routes/ImportsRoute.tsx`, `frontend/src/components/imports/SupportedFormatsRoute.tsx` | Registry | Inspect supported import formats and constraints. |
| `/imports/runs/:runId` | `frontend/src/workbench/routes/ImportsRoute.tsx`, `frontend/src/components/imports/ImportRunDetailRoute.tsx` | Detail record | Inspect one import run, diagnostics, normalized records, and evidence. |
| `/projects` | `frontend/src/workbench/routes/ProjectsRoute.tsx`, `frontend/src/components/projects/ProjectsWorkbench.tsx` | Registry | Manage local project context and switch active project. |
| `/providers` | `frontend/src/workbench/routes/ProvidersRoute.tsx`, `frontend/src/components/providers/ProvidersRouteContainer.tsx` | Registry | Inspect local provider data freshness, diagnostics, and quality. |
| `/reports` | `frontend/src/workbench/routes/ReportsRoute.tsx`, `frontend/src/components/reports/EvidenceCenter.tsx` | Evidence/report | Generate and inspect evidence-backed reports, artifacts, manifests, and history. |
| `/settings` | `frontend/src/workbench/routes/SettingsRoute.tsx`, `frontend/src/components/settings/SettingsRouteContainer.tsx` | Settings/form | Inspect local runtime, persistence, diagnostics, and configuration. |
| `/waivers` | `frontend/src/workbench/routes/WaiversRoute.tsx`, `frontend/src/components/waivers/WaiversWorkbench.tsx` | Registry | Review, create, renew, revoke, and inspect risk acceptance records. |
| `/assets` | `frontend/src/workbench/routes/AssetsRoute.tsx`, `frontend/src/components/assets/AssetsWorkbench.tsx` | Registry | Inspect asset inventory and asset context used in prioritization. |

Route-adjacent IA:

- Finding TTP context is a supporting detail tab under `/findings/:findingId`; it is not a standalone workflow.
- Import diagnostics is a supporting drawer/section under `/imports/runs/:runId`; it is not a separate route.

## 4. Information Hierarchy by Route

| Route | Primary question | Primary object | Primary action | Secondary information | Evidence/provenance display |
| --- | --- | --- | --- | --- | --- |
| `/` | What needs attention in the current project now? | Current project risk posture and readiness. | Open the next finding, provider issue, import run, or report task. | Queue totals, provider freshness, remediation trend, report readiness, recent activity. | Show freshness, source dataset status, and evidence/report readiness as compact status rows. |
| `/findings` | Which known CVE-backed finding should I work first? | Prioritized finding queue. | Filter/sort, inspect quick view, open detail, or start evidence/report action. | Project context, signal totals, assignment/SLA, waiver/VEX state, table pagination. | Each row should expose key source signals and quick view should show provenance/evidence rows. |
| `/findings/:findingId` | Why is this finding prioritized, and what should be done? | One finding with CVE, affected context, evidence, and decision history. | Decide remediation/acceptance path, update state, inspect evidence, or export rationale. | Asset/project metadata, provider freshness, TTP context, related records, history. | Evidence rows for source facts, provider timestamps, parser status, confidence, and caveats. |
| `/imports` | What evidence has been supplied, and what happened to it? | Import run registry. | Start a new import, inspect recent run, or review supported formats. | Import totals, last run, failed/partial status, project/provider mapping. | Each run row should show source file/type, timestamp, parser result, dropped/normalized counts. |
| `/imports/new` | How do I add supplied evidence and verify normalization? | Import draft and validation state. | Select source, configure options, validate, and submit. | Target project, provider mapping, format constraints, preview, warnings. | Validation rows should explain source, parser, unsupported fields, and mapping decisions. |
| `/imports/formats` | Which evidence formats can be imported and what constraints apply? | Supported format registry. | Choose a compatible format or understand why one is unsupported. | Required fields, optional fields, normalized outputs, examples, caveats. | Show format constraints and provenance expectations as definition/status rows. |
| `/imports/runs/:runId` | Did this import produce trustworthy findings and evidence? | One import run. | Inspect diagnostics, open normalized findings, or use run evidence in reports. | Metrics, normalized records, warnings, diagnostics, metadata, artifact references. | Evidence rows for raw source, parser, warnings, dropped records, timestamps, and generated records. |
| `/projects` | Which local project context is active, and what projects exist? | Project registry and active project. | Switch active project or create/update project context. | Storage path, dataset counts, last activity, setup status, project constraints. | Definition rows for storage/local metadata and status rows for project data freshness. |
| `/providers` | Are local provider datasets fresh and usable? | Provider/source registry. | Inspect or refresh/check provider data and resolve gaps. | Snapshots, quality facts, diagnostics, source history, data contracts. | Provider rows must show source, timestamp, freshness, quality, failures, and caveats. |
| `/reports` | What evidence-backed report or decision record can be generated now? | Report artifacts, manifests, decision records, and history. | Generate/export evidence-backed report or inspect artifact provenance. | Run context, quality blockers, manifest deltas, report history, artifact formats. | Evidence rows for artifact lineage, manifest entries, source datasets, quality checks, and assumptions. |
| `/settings` | Is the local Workbench configuration healthy? | Runtime, persistence, provider, and diagnostic settings. | Inspect diagnostics and adjust local configuration. | Local paths, versions, feature availability, diagnostic failures, recovery steps. | Definition/status rows for local paths, runtime facts, provider config, and diagnostic evidence. |
| `/waivers` | Which accepted risks are active, expiring, or need review? | Waiver/risk acceptance register. | Review, create, renew, revoke, or inspect waiver rationale. | Scope, expiration, owner, linked findings/assets, residual risk, review state. | Decision summaries and evidence rows for rationale, linked findings, approvals, expiration, and source facts. |
| `/assets` | Which known assets are affected, and what context changes priority? | Asset inventory and selected asset context. | Filter assets, open asset detail, and use context in finding prioritization. | Ownership, exposure, services, linked findings, import source, confidence. | Evidence rows for source import, service observations, owner confidence, and affected finding links. |

## Cross-Route IA Rules

- The primary object must be visible before supporting charts, summaries, or decorative content.
- The primary action must be obvious from the first viewport without creating a landing page.
- Provider freshness, evidence source, and parser/import state must be row-level facts where they affect trust.
- Decision rationale must distinguish recommendation, evidence basis, residual risk, owner/deadline, and caveat.
- TTP context must remain supporting context derived from supplied evidence and must not imply unsupported inference.
- Settings and setup pages should read as local configuration and diagnostics, not product administration.
