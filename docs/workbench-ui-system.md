# Workbench UI System

Status: canonical UI system documentation for the Workbench frontend. This document defines the target UI contract. It does not migrate route code.

Scope: React/Vite/TypeScript Workbench UI using the current local route adapter, `WorkbenchShell`, route containers, shared components, shared CSS tokens, and TanStack Query. The product is a local-first, single-user vulnerability prioritization and evidence workbench for already-known CVEs from supplied evidence.

Use this document with:

- `docs/workbench-ui-audit.md`
- `docs/workbench-information-architecture.md`
- `docs/workbench-ui-migration-plan.md`
- `frontend/DESIGN.md`
- `frontend/src/components/vpw/README.md`
- `frontend/src/styles/README.md`

## 1. Product UI Principles

These rules are mandatory for Workbench route UI.

- Evidence first, decoration last.
- Tables and compact rows are the default for repeated data.
- Definition lists are the default for object metadata.
- Decision summaries are the default for remediation rationale.
- Evidence rows are the default for proof, source lineage, and provenance.
- Cards are allowed only for bounded summaries, warnings, right-rail summaries, drawer summaries, or empty states.
- No decorative review cards.
- No route-local page headers.
- No route-local card variants.
- No page-specific typography.
- Low color, compact density, thin borders, and no unnecessary shadows.
- Use existing architecture: `AppRouter`, local route adapter, `WorkbenchShell`, route containers, shared VPW/Workbench components, and shared CSS.
- Do not add product scope. The UI must stay focused on supplied evidence, provider trust, prioritization, remediation rationale, risk acceptance, and evidence/report export.

## Visual regression guardrails

These guardrails apply before and during every route migration. The goal is to preserve the best existing operational UI while replacing implementation details incrementally.

1. Preserve the best existing visual baseline before replacing implementation details.
2. Canonical components must not be forced when they degrade width, density, scanability, or scroll behavior.
3. Dense operational queues may keep route-specific table shells until shared table wrappers can match the same full-width, table-first behavior.
4. Page scroll ownership must remain native and predictable. Do not intercept wheel events for artificial smooth scrolling.
5. Route migrations must be incremental and reversible.
6. Every route migration starts with a no-code visual baseline audit.
7. Every implementation pass must name what visual baseline is preserved, which component is replaced, which behavior is unchanged, and which screenshots should be checked manually.
8. Badge labels in dense tables must stay compact: `Critical`, `High`, `Medium`, `Low`, `Open`, `Fixed`, `KEV`, `EPSS 94.5%`, `CVSS 10.0`, `Risk 100.0`.
9. Do not replace a stable route-local layout wrapper with a shared wrapper unless the shared wrapper preserves or improves the visual result.
10. Passing TypeScript/build tests is not sufficient for UI migration acceptance; visual review is required.
11. If a migration causes a visual regression, revert or repair before touching another route.
12. Scroll regressions are blocker bugs and must be fixed before continuing visual migration.

## 2. Typography Scale

Typography must be shared and token-driven. Route files should not create their own heading scales, letter spacing, or page-specific text classes.

| Text role | Canonical usage | Target treatment | Examples |
| --- | --- | --- | --- |
| Page eyebrow | Short route family or object type shown by the shell-owned page header. | Uppercase or small label style, muted color, compact line height. | `Operate`, `Evidence center`, `Finding detail`. |
| Page title | One shell-owned title per route from route metadata. | Highest page text size, semibold, no negative tracking, no route-local duplicate. | `Findings`, `Providers`, `Risk acceptance`. |
| Page description | One shell-owned sentence explaining route purpose. | Muted body text, one to two lines, no marketing copy. | "Prioritize known findings using supplied evidence and provider signals." |
| Section title | Title for a bounded page section below the page header. | Medium heading, semibold, compact margin. | `Remediation queue`, `Provider sources`, `Evidence artifacts`. |
| Subsection title | Title for a small group inside a drawer, rail, form, or detail section. | Small heading, semibold, tight spacing. | `Decision basis`, `Source evidence`, `Runtime facts`. |
| Body text | Explanatory copy, descriptions, rationale, and caveats. | Standard body size, normal line height, muted when secondary. | Rationale body in a decision summary. |
| Metadata/labels | Field labels, timestamps, source names, owner labels, diagnostic labels. | Small label style, muted color, consistent case. | `Last updated`, `Provider`, `Confidence`. |
| Table text | Queue, registry, and history row text. | Compact body size, stable row height, no oversized chips. | Finding ID, asset name, source status. |
| Badge text | Short state or signal labels only. | Small label text, constrained width, no sentence copy. | `Open`, `Stale`, `KEV`, `Accepted`, `High EPSS`. |

Implementation notes:

- Keep page-level typography in `frontend/src/components/app/AppShell.tsx` and route metadata in `frontend/src/lib/app-route-config.ts`.
- Keep shared typography classes in shared styles, preferably under `frontend/src/styles/vpw-components.css` or a future Workbench shared stylesheet.
- Remove route-local typography from `dashboard.css`, `findings.css`, `finding-detail-*.css`, `assets.css`, `providers.css`, `waivers.css`, and local TSX class strings as routes migrate.

## 3. Layout System

Every Workbench route should follow this structure.

```text
Workbench shell
  Page header
  Route body
    Optional context bar
    Optional metric strip
    Primary content
      Tables, lists, detail sections, forms, or report/evidence sections
    Optional right rail
    Optional detail drawer
```

### Workbench Shell

Owned by `frontend/src/workbench/WorkbenchShell.tsx` and `frontend/src/components/app/AppShell.tsx`.

- Provides navigation, shell scroll ownership, global page title, route description, and route boundary.
- Must remain mounted once in `frontend/src/AppRouter.tsx`.
- Must not be bypassed by route-level page shells.

### Page Header

Owned by the shell and route metadata.

- Source: `frontend/src/lib/app-route-config.ts`.
- One page title per route.
- Route components must not render large hero headers that repeat the page title.
- Route components may render a context bar or section title when the content needs local context.

### Optional Context Bar

Use when a route needs current object/context state before the primary content.

- Good for active project, provider freshness, import run, selected finding, selected asset, report run, waiver scope, or runtime health.
- Should be compact and row-based.
- Should include one primary action at most unless the route requires a small action group.

### Optional Metric Strip

Use for operational counts and health facts.

- Use a horizontal metric strip, not a grid of decorative metric cards.
- Keep values compact.
- Prefer status/signal badges for state rather than color-heavy cards.

### Primary Content

Primary content depends on the page archetype:

- Overview: compact operating summary plus next-action content.
- Queue: table-first priority list.
- Registry: table/list-first inventory.
- Detail record: object summary, decision summary, evidence/provenance, metadata.
- Evidence/report: artifacts, manifests, report history, quality facts, evidence rows.
- Settings/form: compact forms and diagnostic definition/status rows.

### Optional Right Rail

Use only when bounded supporting information should remain visible beside primary content.

- Good for next action, current object facts, decision state, data freshness, and blocking warnings.
- Not a second dashboard.
- Not a stack of decorative cards.

### Tables, Lists, and Details

Use these defaults:

- Repeated records: `DataTableFrame`.
- Compact repeated facts: compact list or status rows.
- Object metadata: `DefinitionList`.
- Rationale: `DecisionSummary`.
- Source proof: `EvidenceRow`.
- Empty or blocked content: `EmptyState` or `Callout`.

## 4. Component Contract

Canonical components should be introduced as shared Workbench/VPW components or adapters over existing `frontend/src/components/vpw/*` primitives. Avoid parallel route-specific implementations.

| Component | Use when | Required content | Must not be used for |
| --- | --- | --- | --- |
| `PageHeader` | The shell renders route title/description/eyebrow. | Eyebrow, title, description, optional top-level action. | Route-local heroes, duplicate h1/h2 page headers, marketing-style copy. |
| `ContextBar` | Current route context changes how the user reads the page. | Object/context label, key facts, freshness/state, primary action. | Repeated records, dashboards, decorative summaries. |
| `MetricStrip` | Showing compact counts, status totals, freshness totals, or operational counters. | 2-6 metrics with label, value, optional trend/status. | Large KPI cards, per-record metadata, repeated table content. |
| `PageSection` | Grouping a primary content area. | Optional section title, description, actions, body slot, loading/empty slot. | Creating card chrome around every page block. |
| `FilterBar` | Filtering or searching a queue/registry/table. | Search, select/toggle controls, reset, result count when useful. | Route-specific toolbar layouts, unrelated page actions. |
| `DataTableFrame` | Rendering queue, registry, history, source, finding, asset, project, waiver, provider, or artifact rows. | Header slot, action slot, table, loading, empty, pagination, responsive row mode. | One-off metric panels or narrative content. |
| `StatusBadge` | Lifecycle or state labels. | One short state string and semantic variant. | Risk signals, provider source labels, long explanations. |
| `SignalBadge` | Evidence, risk, provider, or prioritization signals. | Signal label, optional value/confidence, semantic variant. | Lifecycle state or action labels. |
| `DefinitionList` | Object metadata and diagnostic facts. | Label/value rows, optional grouped sections, optional copy/action per row. | Repeated records that need sorting/filtering, narrative decision rationale. |
| `DecisionSummary` | Explaining remediation, acceptance, or report decision rationale. | Recommendation, why-now, evidence basis, residual risk, owner/deadline when available, caveats. | Generic card summary, table replacement, unsupported inference. |
| `EvidenceRow` | Showing proof/provenance. | Source, timestamp, provider/parser, artifact or record reference, confidence/status, caveat. | Decorative citation cards or unrelated metadata. |
| `DetailRail` | Persistent side summary next to detail or report content. | Current object facts, next action, state/freshness, compact status rows. | A full dashboard, duplicate primary content, route navigation. |
| `DetailDrawer` | Inspecting a row/object without leaving a queue or registry. | Object header, status summary, sections, definition lists, evidence rows, sticky actions. | Full route replacement, decorative card stack. |
| `EmptyState` | Empty table, empty section, unavailable drawer content, or no configured local data. | Short title, direct explanation, optional action. | Warnings, errors with remediation steps, repeated route copy. |
| `Callout` | Warning, blocked state, degraded data, stale provider, validation issue, or important caveat. | Severity, title, body, optional metadata/action. | Decorative info boxes, page headers, normal metadata rows. |

### Existing Components to Reuse or Wrap

Use these as implementation starting points:

- `frontend/src/components/vpw/WorkbenchComponents.tsx`
- `frontend/src/components/vpw/VpwPageContainer.tsx`
- `frontend/src/components/vpw/VpwLayout.tsx`
- `frontend/src/components/vpw/VpwFilterBar.tsx`
- `frontend/src/components/vpw/VpwDataTable.tsx`
- `frontend/src/components/vpw/VpwTableCard.tsx`
- `frontend/src/components/vpw/VpwBadge.tsx`
- `frontend/src/components/vpw/VpwSemanticBadges.tsx`
- `frontend/src/components/vpw/VpwKeyValueList.tsx`
- `frontend/src/components/vpw/VpwEmptyState.tsx`
- `frontend/src/components/vpw/VpwSkeletonStack.tsx`
- `frontend/src/components/vpw/VpwStatusBanner.tsx`
- `frontend/src/components/ui/sheet.tsx`
- `frontend/src/components/ui/tabs.tsx`

Components to narrow or retire from Workbench route use:

- Generic `Card` route wrappers from `frontend/src/components/ui/card.tsx`.
- Card-based state wrappers in `frontend/src/components/states/EmptyState.tsx`, `LoadingSkeleton.tsx`, and `ErrorState.tsx`.
- Former route-local metric-card implementations.
- Direct route composition with `VpwMetricStrip` and `VpwCompactMetric`; route
  code should use the canonical `MetricStrip` adapter, while VPW primitives and
  showcase evidence may continue to use the lower-level components.
- Route-local hero, tab, drawer, panel, and badge variants listed as baseline
  findings in `docs/workbench-ui-audit.md`.

### Component Usage Examples

Import the canonical contract from the VPW barrel:

```tsx
import {
  Callout,
  ContextBar,
  DataTableFrame,
  DecisionSummary,
  DefinitionList,
  DetailDrawer,
  DetailRail,
  EmptyState,
  EvidenceRow,
  FilterBar,
  MetricStrip,
  PageHeader,
  PageSection,
  SignalBadge,
  StatusBadge,
} from "@/components/vpw"
```

Use `PageHeader` only where the shell owns route metadata, not inside route-local hero blocks:

```tsx
<PageHeader
  eyebrow="Operate"
  title="Findings"
  description="Prioritize known findings using supplied evidence and provider signals."
  status={<StatusBadge status="fresh" label="Local data ready" />}
/>
```

Use `ContextBar` for compact project, provider, run, or object context before primary content:

```tsx
<ContextBar
  title="Active project"
  description="Local context used for this queue."
  items={[
    { label: "Project", value: projectName },
    { label: "Provider data", value: "NVD", status: { status: "fresh" } },
    { label: "Import run", value: runId, signal: { kind: "provider", value: "CSV" } },
  ]}
/>
```

Use `MetricStrip` for three to five compact facts. Do not replace it with large dashboard cards:

```tsx
<MetricStrip
  metrics={[
    { label: "Open", value: openCount, tone: "info" },
    { label: "KEV", value: kevCount, tone: "critical" },
    { label: "Accepted", value: acceptedCount, tone: "success" },
  ]}
/>
```

Use `PageSection`, `FilterBar`, and `DataTableFrame` for queues and registries:

```tsx
<PageSection
  title="Remediation queue"
  description="Known findings ordered by local prioritization signals."
>
  <DataTableFrame
    title="Findings"
    filters={
      <FilterBar
        searchLabel="Finding search"
        searchPlaceholder="Search CVE, asset, owner"
        searchValue={query}
        onSearchChange={setQuery}
      />
    }
    columns={columns}
    data={rows}
    getRowKey={(row) => row.id}
  />
</PageSection>
```

Use `DefinitionList` for metadata, `DecisionSummary` for rationale, and `EvidenceRow` for provenance:

```tsx
<DecisionSummary
  whyThisPriority="Known exploited status and affected exposed service raise urgency."
  recommendedAction="Patch in the next maintenance window."
  riskScore={<SignalBadge kind="cvss" value={9.8} />}
  primaryDriver={<SignalBadge kind="kev" />}
  decisionBasis="Supplied asset evidence, provider snapshot, and waiver state."
/>

<DefinitionList
  items={[
    { label: "Owner", value: owner },
    { label: "SLA", value: dueDate },
    { label: "Service", value: serviceName },
  ]}
/>

<EvidenceRow
  source="Provider snapshot"
  title="CISA KEV match"
  provider="KEV"
  timestamp={snapshotTime}
  signal={{ kind: "kev" }}
  description="Matched from the local provider dataset used for this run."
/>
```

Use `DetailRail` or `DetailDrawer` for bounded supporting context:

```tsx
<DetailRail title="Decision state" status={<StatusBadge status="in_review" />}>
  <DefinitionList items={decisionFacts} />
</DetailRail>

<DetailDrawer
  open={open}
  onOpenChange={setOpen}
  title="Finding quick view"
  status={<StatusBadge status="open" />}
>
  <DecisionSummary {...summary} />
  {evidence.map((item) => (
    <EvidenceRow key={item.id} {...item} />
  ))}
</DetailDrawer>
```

Use `EmptyState` for no-data states and `Callout` for deterministic warnings/errors/caveats:

```tsx
<EmptyState
  title="No provider data"
  description="Import or refresh local provider snapshots to populate this section."
/>

<Callout severity="warning" title="Snapshot is stale">
  Provider freshness affects confidence in prioritization signals.
</Callout>
```

## 5. Anti-Patterns

These are explicitly forbidden for Workbench route UI:

- Cards for every section.
- Dashboards on every page.
- Route-local typography.
- Route-local badges.
- Route-local table styles.
- Shadow-heavy panels.
- Decorative icons without information value.
- Large hero cards on operational pages.
- New visual patterns without updating this UI-system document first.
- Duplicating the shell page title inside a route.
- Replacing table/list semantics with review cards for repeated data.
- Hiding source evidence, provider freshness, parser status, or provenance behind decorative summaries.
- Adding new dependencies for visual polish when shared primitives can solve the problem.
