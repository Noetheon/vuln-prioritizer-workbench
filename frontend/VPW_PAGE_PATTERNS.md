# VPW Page Pattern Contract

Status: implementation contract for VPW workbench screens.

This file turns `frontend/DESIGN.md` into concrete page rules. Codex and human
contributors should use it before editing route UI. The goal is a calm,
compact, evidence-first security workbench inspired by Linear precision, Sentry
triage discipline, and HashiCorp infrastructure credibility without copying any
brand surface.

## Global Structure

Every workbench route should use the same order:

1. AppShell route title and route description.
2. Optional page command section for route-level actions and project/run
   context.
3. Compact metric strip only when the numbers help choose the next action and
   are not already represented in the command/context section.
4. Filters/toolbars directly above the data they control.
5. Primary data surface: table, register, evidence manifest, or wizard body.
6. Secondary analysis, provenance, history, or governance detail.

Do not add route-local hero compositions. The AppShell already owns the route
heading. Inside the route, use compact section headers.

## Allowed Page Types

### List And Register Routes

Examples: Triage, Assets, Risk Acceptance, Projects directory.

- Header: `VpwSectionHeader` with an eyebrow, 16-20px title, and one short
  description.
- Summary: one `VpwMetricStrip` with separated, responsive
  `VpwCompactMetric` cards. Cards should stay white, card-like, and use their
  extra width through stable card proportion, a vertical label/value/description
  stack, and responsive icon/type scale instead of becoming grey fact rows,
  merged strips, or flat wide bars with copy pushed to the far edge. Do not add
  a second project/provider/status strip under it.
- Controls: one `VpwFilterBar` or equivalent local filter row.
- Data: `VpwTableCard` with the table/register as the main object.
- Secondary content: unframed sections or panels, not another decorative card
  wall.

### Detail Routes

Examples: Finding detail, import run detail.

- Start with a compact identity band: id, status, primary action, key signals.
- Use tabs only when they separate distinct analyst tasks.
- Prefer key-value rows and evidence tables over repeated review cards.
- Keep sidebars factual: owner, service, state, SLA, evidence, actions.

### Wizard Routes

Examples: New import.

- Use a stable two-column wizard shell: step rail plus current step.
- Selection choices may be cards because they are selectable objects.
- Guidance and summary content should be list rows or key-value groups, not
  large explanatory cards.

### Evidence Routes

Examples: Evidence Center, Data Sources.

- Lead with run/provider context and readiness state.
- Artifact lists, manifests, checksums, and provider snapshots should be tables
  or key-value lists.
- Use cards only for downloadable artifact objects or stateful generation
  controls.
- Do not place a second KPI/summary strip between the run/provider context and
  the primary artifact inventory. If a fact is needed before artifact review, it
  belongs in the context section; if it explains generated files, it belongs in
  the table, manifest, or artifact object.

### Settings/System Routes

Examples: Workspace Settings.

- Treat settings as a console, not a dashboard.
- Put route-level runtime status in the command/context header as badges or
  concise state labels.
- Use a single primary console surface, usually `VpwTableCard` with
  `VpwDataTable`, for workspace/runtime/provider facts.
- Prefer fact rows, tabs, and compact panels for secondary runtime detail.
- Avoid metric cards unless they summarize actual operational state that
  changes the next user action; never use static facts like local mode or
  single-user access as KPI cards.

## Component Decision Matrix

Use this matrix before adding markup to a route. If none of these rows fits,
the route probably needs a shared VPW primitive or a documented domain owner,
not another local card/header pattern.

| Need | Use | Do not use |
| --- | --- | --- |
| Page rhythm and vertical grouping | `VpwPageStack` then `VpwSection` | Route-local `div` stacks with unrelated gaps |
| Section title, eyebrow, and short description | `VpwSectionHeader` | Local `h2`/`p` typography utilities |
| Route-level command/context area | `VpwCommandPanel` | A decorative hero or marketing-style header |
| Command header divider | The built-in `VpwCommandPanel` header divider from `vpw-components.css` | Route-local `.vpw-command-panel__header` borders or page-specific divider spacing |
| Primary register, queue, inventory, or report history | `VpwTableCard` with `VpwDataTable` | Repeated review cards for tabular records |
| Metadata, provenance, settings facts, checksums, run details | `VpwKeyValueList` or compact definition rows | A card per field |
| KPI/status summaries, queue counts, selected project state, provider freshness, or import run state | `VpwMetricStrip` with separated responsive `VpwCompactMetric` cards using a stable card ratio and vertical content stack | Grey fact rows, merged segmented strips, flat stretched bars with right-floating descriptions, nested badges as values, second context strips, or route-local metric wrappers |
| Facts that duplicate the route command/context section | Fold into the command/context section or remove | A second `VpwMetricStrip` immediately below the command/context section |
| Framed form, bounded tool, drawer body, or grouped facts | `VpwPanel` | Floating cards inside page sections |
| Warning, demo/sample, failed, success, or blocked state | `VpwStatusBanner` | Color-only callouts or decorative panels |
| Selectable import/source/action choice | `VpwSelectionCard` or a domain choice component | Generic cards without selected/focus state |
| Downloadable artifact object | Evidence artifact card component | Cards for every prose paragraph |
| Pure explanatory copy or local guidance rows | No card; use rows, dividers, or body copy | `Card`, `VpwPanel`, or metric surfaces |

Avoid raw `Card` unless the object is genuinely a repeated object, selectable
choice, modal/drawer content, or artifact card. If a route needs the same card
shape twice, promote it into `frontend/src/components/vpw`.

## Codex Instruction

For future UI work, the instruction is:

> Use `frontend/DESIGN.md` plus `frontend/VPW_PAGE_PATTERNS.md`; do not add new
> route-local card, heading, shadow, radius, or page-stack patterns without an
> existing VPW wrapper or a documented VPW component follow-up.

## Density Rules

- Route title: AppShell only, 24-32px.
- Section title: 16-20px.
- Card/object title: 14-16px.
- Body copy: 14px in work surfaces, 16px only for route-level explanation.
- Table labels and stable metadata labels: 12px mono uppercase.
- Default vertical gap between major sections: 16-20px.
- Default border radius: 8px or less.
- Default elevation: none; rely on hairline borders.

## Anti-Patterns

- Do not create a new local hero for a normal workbench page.
- Do not style every information group as a floating card.
- Do not nest cards inside cards; use rows, dividers, key-value groups, or
  tables.
- Do not create route-local KPI wrappers like dashboard/findings/assets metric
  strips; shared VPW primitives own the visual shape.
- Do not merge KPIs into one segmented control-like block. They should remain
  separate cards with consistent sizing and spacing.
- Do not replace KPI cards with grey fact rows. On wide workbench surfaces,
  `VpwCompactMetric` must keep card proportion and scale internally: value,
  label, description, and icon should stay as one compact vertical reading unit
  rather than splitting across the whole width.
- Do not stack a context strip and a summary strip when they describe the same
  selected project/run/provider state.
- Do not use large marketing headings inside route content.
- Do not use color as decoration. Severity and state colors must carry meaning.
- Do not add route-local color ladders, shadows, or radii.

## Implementation Gate

Before finishing UI work, inspect the changed route in a browser and answer:

- Does the page follow one allowed page type?
- Is the primary data surface obvious within the first viewport?
- Are metrics compact and action-relevant?
- Are headers the same scale as comparable routes?
- Are cards used only for repeated objects, tools, states, dialogs, or
  selectable choices?
- Are provider/run/evidence facts visible where decisions depend on them?
