# VPW Product Components

These components install the shared Vuln Prioritizer Workbench product patterns from the design system kit. They are intentionally small wrappers around the existing shadcn-compatible primitives, using the VPW token variables from `frontend/src/index.css`.

Use them when refactoring routes in later passes so Dashboard, Findings, Finding Detail, and Evidence Center share the same containers, cards, badges, tables, and product states.

Use VPW wrappers for reusable Workbench structure: page containers, sections,
panels, metric cards, status/empty states, badges, toolbars, tables, and
evidence cards. Use route-local Tailwind for one-off alignment, spacing around a
specific form, or layout that is not shared across routes. If the same
route-local pattern is needed by a second route, promote it into a VPW component
or a documented domain CSS owner instead of adding a fallback stylesheet.

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
