# VPW UI/UX Redesign Direction

Source of truth: `Vuln_Workbench_UIUX_Masterplan_Codex.md`.

This note is a narrow visual-reference synthesis for the Workbench redesign. It is subordinate to the masterplan, the existing VPW design token system, and the current VPW/shadcn component layer. It must not override route, API, query-key, generated-client, or product guardrails.

## Reference Scope

The limited reference review used only:

- `linear.app/DESIGN.md`
- `sentry/DESIGN.md`
- `hashicorp/DESIGN.md`

These references are not brand targets. Do not copy names, logos, proprietary product surfaces, exact color palettes, fonts, or trademarked patterns.

## Extracted Principles

- Density: prefer compact, scan-first work surfaces with clear row hierarchy, tight chips, and short headers.
- Hierarchy: make the primary work object visible early; move diagnostics, long explanations, and advanced controls into drawers, tabs, or disclosures.
- Navigation rhythm: group work by user intent rather than implementation area: operate, prepare, govern, system.
- Severity and status: keep risk, lifecycle status, source identity, signal evidence, counts, and metadata visually distinct through semantic components.
- Table readability: avoid paragraph cells; use primary text, secondary metadata, and capped signal clusters.
- Drawer and tab behavior: use drawers for selected-object preview or task flows, and tabs for detail categories of one object.
- Tone: quiet enterprise-security UI; factual, local-first, defensive, and evidence-oriented.

## VPW-Specific Rules

- Preserve existing VPW tokens from `frontend/src/styles/tokens.css` and component styles in `frontend/src/styles/vpw-components.css`.
- Do not hard-code new hex colors in feature components.
- Do not introduce external fonts or new motion libraries.
- Use existing `VpwBadge`, `VpwDataTable`, `VpwMetricCard`, `VpwStatusBanner`, `VpwEmptyState`, and related VPW primitives before creating new components.
- New semantic primitives should wrap or compose VPW primitives rather than replace the design system.
- Component text must remain defensive and must not imply scanning, exploitation, proof of compromise, SaaS auth, RBAC, or multi-user governance.

## PR1 Interpretation

PR1 should establish semantic badge primitives before larger page restructuring:

- `RiskBadge` for priority/risk bucket labels.
- `RiskScoreBadge` for numeric or missing risk scores.
- `StatusLozenge` for lifecycle, freshness, readiness, and review states.
- `SignalChip` for meaningful signals such as KEV, EPSS, CVSS, ATT&CK mapped, VEX, and provider evidence.
- `CountBadge` for counts and overflow markers.
- `MetaTag` for low-emphasis metadata such as environment, owner, service, and exposure.
- `SourceMark` for provider/source identity.
- `VpwSignalCluster` for capped, wrapped signal groups.

The implementation should reduce route-local pill systems while preserving current page structure for PR1.
