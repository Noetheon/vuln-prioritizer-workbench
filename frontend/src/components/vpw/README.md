# VPW Product Components

These components install the shared Vuln Prioritizer Workbench product patterns from the design system kit. They are intentionally small wrappers around the existing shadcn-compatible primitives, using the VPW token variables from `frontend/src/index.css`.

Use them when refactoring routes in later passes so Dashboard, Findings, Finding Detail, and Evidence Center share the same containers, cards, badges, tables, and product states.

Current design direction: `frontend/DESIGN.md` defines the VPW Precision Light
Analyst designset. Apply these wrappers as the default read/write analyst
surface before adding route-local structure.

Use VPW wrappers for reusable Workbench structure: page containers, sections,
panels, metric cards, status/empty states, badges, toolbars, tables, and
evidence cards. Use route-local Tailwind for one-off alignment, spacing around a
specific form, or layout that is not shared across routes. If the same
route-local pattern is needed by a second route, promote it into a VPW component
or a documented domain CSS owner instead of adding a fallback stylesheet.

Precision Light Analyst usage rules:

- Use tables, filter bars, toolbars, badges, and key-value lists for scan-heavy
  read surfaces.
- Keep table workspaces as one visual system: a `VpwSectionHeader`, optional
  `VpwFilterBar`, and `VpwDataTable` should sit in the same `VpwSection` or in
  a route-specific table panel with identical padding rhythm. Do not put search
  controls in a table header unless the surface is intentionally compact, such
  as the dashboard queue preview.
- Order reusable filters by decision context: project/scope first, search next,
  domain text filters after that, then select/status/view controls, and reset or
  advanced actions at the end. This keeps matching tables from feeling randomly
  rearranged between routes.
- Use `vpw-table-actions` plus `vpw-table-action-button` for repeated table-row
  commands. Icon-only actions need an `aria-label` and tooltip; reserve text
  buttons for primary commands outside repeated table rows.
- Use fields, segmented controls, selection cards, status banners, and explicit
  action buttons for write surfaces such as decision capture, waiver review,
  report generation, and provider verification.
- Keep severity and provider state visible through component tone props and
  state copy. Color alone is not enough.
- Preserve demo/sample labeling whenever showcase or seeded evidence could be
  mistaken for production evidence.
- Keep cards shallow. Do not nest VPW cards inside other VPW cards; use panels,
  dividers, or key-value lists for secondary grouping.

Installed VPW product components:

- `VpwAppFrame`
- `VpwPageContainer`
- `VpwSection`
- `VpwGrid`
- `VpwPanel`
- `VpwSectionHeader`
- `VpwMetricCard`
- `VpwBadge`
- `VpwBreadcrumbs`
- `VpwDataTable`
- `VpwDemoBanner`
- `VpwEmptyState`
- `VpwStatusBanner`
- `VpwToolbar` / `VpwToolbarGroup`
- `VpwField`
- `VpwFilterBar`
- `VpwSegmentedControl`
- `VpwSelectionCard`
- `VpwKeyValueList`
- `VpwProgress`
- `VpwTimeline`
- `VpwTokenSwatch`
- `VpwTypographySpec`
- `VpwSpacingSpec`
- `VpwElevationSpec`
- `VpwCodeBlock`
- `VpwChecksum`
- `VpwStateBlock`
- `VpwSkeletonStack`
- `VpwFindingSummaryCard`
- `VpwAssetContextCard`
- `VpwWaiverDecisionCard`
- `VpwAttackTechniqueCard`
- `VpwImportStepCard`
- `VpwReportHistoryCard`
- `VpwProviderSnapshotCard`
- `VpwEvidenceFlowCard`
- `VpwEvidenceArtifactCard`
- `VpwEvidenceManifestCard`
- `VpwExecutiveDecisionSummary`
- `VpwDesignSystemShowcase`

`VpwDesignSystemShowcase` is for evidence and review surfaces only. Do not mount
it as primary product UI unless the task explicitly asks for a design-system
page.
