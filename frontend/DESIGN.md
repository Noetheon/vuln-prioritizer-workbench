# VPW Precision Light Analyst Designset

Status: durable design direction for read/write VPW redesign slices.

Source inspiration: `frontend-design-awesome-design-md` only, adapted from
Linear precision, Sentry incident triage, and HashiCorp enterprise
infrastructure discipline. This is not a brand clone. VPW keeps its existing
tokens, component wrappers, and product vocabulary.

Implementation contract: `frontend/VPW_PAGE_PATTERNS.md` defines the allowed
route structures and component choices. Treat it as the concrete gate for UI
edits after reading this designset.

## Product Posture

VPW is a security operations workbench for analysts who need to read evidence,
write decisions, and explain why a vulnerability is prioritized. The interface
must feel calm, exact, and operational. It should support repeated scanning,
comparison, filtering, annotation, waiver review, and evidence export without
marketing drama.

Precision Light Analyst means:

- Light-first application surfaces with dark mode supplied by tokens.
- Dense but legible tables, cards, and evidence panels.
- Explicit read/write affordances for analyst decisions, notes, filters,
  waivers, and report generation.
- Severity color used for meaning, never decoration.
- Small-radius, hairline-bordered product surfaces.
- Copy that names evidence, freshness, owner, decision, and next action.

## Visual Principles

1. Use light canvas discipline.
   App ground is quiet and slightly cool. Cards stay white, panels stay
   near-white, and borders do most of the separation. Avoid dark hero blocks,
   large gradients, decorative orbs, and photo-led layouts.

2. Make risk scannable before it is dramatic.
   Critical, warning, success, info, and support tones should appear as badges,
   state banners, progress bars, and restrained accents. A full surface should
   turn critical only when the whole object is a critical state.

3. Keep analyst density.
   Default table rows, toolbar groups, filters, cards, and key-value lists must
   support comparison across many findings. Avoid oversized headings inside
   route content and avoid card stacks that hide tabular relationships.

4. Show provenance and write state.
   Read surfaces should expose provider snapshot, generated time, source,
   checksum, owner, and evidence confidence. Write surfaces should expose draft,
   reviewed, accepted, blocked, verified, and demo/sample states.

5. Prefer reusable VPW primitives.
   Shared structure belongs in `frontend/src/components/vpw` and shared styling
   belongs in `frontend/src/styles/vpw-components.css`. Route-local styling is
   allowed only when the pattern is not reusable.

## Token Mapping

Use the installed VPW variables from `frontend/src/styles/tokens.css`.

- Canvas: `--vpw-bg-app`
- Page: `--vpw-bg-page`
- Card: `--vpw-bg-card`
- Panel: `--vpw-bg-panel`
- Border: `--vpw-border-default`, `--vpw-border-subtle`,
  `--vpw-border-strong`
- Text: `--vpw-text-primary`, `--vpw-text-secondary`, `--vpw-text-muted`
- Focus: `--vpw-focus-ring`
- Primary action: `--primary` / `--vpw-text-primary` with
  `--primary-foreground`
- Link, focus, and informational state: `--vpw-blue`
- Evidence/security accent: `--vpw-teal`
- Success: `--vpw-green`
- Warning: `--vpw-amber`
- Critical/destructive: `--vpw-red`
- Support/context: `--vpw-violet` mapped to a cool slate support tone, not
  purple.
- Chart severity: `--vpw-chart-critical`, `--vpw-chart-high`,
  `--vpw-chart-medium`, `--vpw-chart-low`
- Chart rankings and trend: `--vpw-chart-risk`, `--vpw-chart-trend`,
  `--vpw-chart-grid`
  Use a clearer cobalt/cyan chart accent set for analytical energy; avoid
  charcoal-only bars and avoid returning to purple.
- Ranked entity charts: `--vpw-chart-rank-1` through `--vpw-chart-rank-5`.
  Use this ordered cool palette for Top Services/Assets so repeated critical
  services do not collapse into a single solid severity color.
- Radius: `--vpw-radius-sm`, `--vpw-radius-md`, `--vpw-radius-lg`,
  `--vpw-radius-xl`, `--vpw-radius-pill`
- Elevation: `--vpw-shadow-0`, `--vpw-shadow-1`, `--vpw-shadow-2`,
  `--vpw-shadow-3`

Text-bearing secondary and semantic tokens are AA-adjusted from the source
palette. Do not use quieter decorative grays or bright semantic accents for
small text on white surfaces.

Do not introduce parallel color constants in route code. If the current token
set cannot express a required product state, document the gap before adding any
new token in a separate token-owned change.

## Type And Density

Use the existing Inter/system stack. Keep letter spacing at `0` unless the
existing VPW class already defines uppercase labels. Use compact type inside
work surfaces:

- Route title: 24-32px, semibold, tight but not display scale.
- Section title: 16-20px, semibold.
- Card title: 14-16px, semibold.
- Body: 14px for dense product copy, 16px for explanatory route copy.
- Labels and table headers: 12px, semibold/bold, uppercase only for stable
  metadata labels.
- Mono: CVE IDs, checksums, manifest paths, run IDs, and provider identifiers.

Avoid viewport-scaled typography. Text must wrap cleanly inside buttons, cards,
tables, sidebars, banners, and mobile panels.

## Layout

- Use `VpwPageContainer` for the route content boundary.
- Use `VpwSection`, `VpwGrid`, `VpwPanel`, and `VpwSectionHeader` for repeated
  page rhythm.
- Use `frontend/VPW_PAGE_PATTERNS.md` to choose the page type before adding
  route-local markup.
- Keep cards at 8px radius or less unless an existing VPW wrapper maps to a
  token with the same value.
- Use full-width unframed route sections. Cards are for repeated objects,
  panels, states, dialogs, and framed tools.
- Keep filter/search/action toolbars adjacent to the data they modify.
- On mobile, preserve task order: summary, filters/actions, primary list,
  selected item details, evidence or history.
- Do not nest cards inside cards. Use panels, dividers, or key-value lists for
  secondary grouping inside a card.

## Read/Write Analyst Patterns

Read patterns:

- Finding summary: CVE, priority, exploit signal, affected asset, owner,
  current status, and recommended next action.
- Evidence manifest: generated time, run ID, sources, checksum, file list, and
  demo/production distinction.
- Provider freshness: source, snapshot age, status, and fallback mode.
- ATT&CK context: reviewed mapping, tactic, technique, and confidence.

Write patterns:

- Decision capture: recommendation, owner, due date, waiver state, and review
  note.
- Filters: priority, KEV, EPSS range, asset exposure, owner, status, and source
  freshness.
- Report actions: generate, verify, download, and copy/checksum controls with
  visible busy, success, blocked, and demo states.
- Waivers: require reason, review date, owner, evidence attachment, and clear
  accepted-risk language.

Controls should use recognizable icons where useful, especially generate,
download, refresh, verify, search, filter, copy, and external-link actions.
Do not replace standard controls with explanatory text blocks.

## Components

Use VPW wrappers for:

- App frame previews and page containers.
- Sections, grids, panels, section headers, metric cards, badges, breadcrumbs.
- Toolbars, filter bars, fields, segmented controls, selection cards.
- Data tables, empty states, status banners, skeletons, state blocks.
- Finding, asset, waiver, ATT&CK, import, provider, report, and evidence cards.
- Foundation specs and design-system showcase evidence.

Use shadcn primitives through the existing VPW wrappers or local composition
when the primitive is genuinely route-specific. Promote duplicated route-local
patterns into a VPW component in a separate component-owned change.

## State Language

Allowed product tones:

- `critical`: exploited, destructive, blocked, failed verification.
- `warning`: demo/sample, stale provider, waiver review, incomplete evidence.
- `success`: verified, fresh, complete, generated, accepted import.
- `info`: neutral system context, snapshot mode, queued work.
- `support`: secondary analytical context, ATT&CK, report metadata.
- `neutral`: default inactive, unfiltered, not yet reviewed.

Demo/sample data must be visibly labeled. Do not present generated examples as
production evidence.

## Accessibility And Interaction

- Every interactive element needs a visible focus state from `--vpw-focus-ring`
  or the shadcn token bridge.
- Tables must remain horizontally scrollable instead of crushing columns.
- Icons inside buttons need accessible names from the button text, tooltip, or
  `aria-label`.
- Color cannot be the only status signal; pair tone with labels or state copy.
- Busy, disabled, empty, error, and success states must preserve layout size to
  avoid jitter during analyst workflows.

## Do Not

- Do not use `frontend-design-google-design-md` for this direction.
- Do not add token files, route rewrites, AppShell changes, package changes, or
  tests as part of documentation-only designset updates.
- Do not introduce decorative gradients, blobs, bokeh, photo heroes, oversized
  marketing hero sections, or one-note purple/blue palettes.
- Do not style every surface as a card. Prefer clear information hierarchy.
- Do not hide write actions behind prose. Use controls with explicit states.
