# VPW-AUD-206 Frontend Color Scan

Date: 2026-05-07

## Command

```bash
rg -n '#[0-9a-fA-F]{3,8}|rgb\(' frontend/src
```

## Result Summary

The retired `frontend/src/styles/workbench-fallback.css` compatibility layer is
removed from the active stylesheet import path. Dashboard, Findings, Login,
Base, VPW component, and chart colors touched by VPW-AUD-206 now use VPW tokens
or token-derived `color-mix(...)` values.

Remaining scan hits are allowlisted below:

```text
   4 frontend/src/components/vpw/VpwDesignSystemShowcase.tsx
  31 frontend/src/lib/vpw-tokens.json
  31 frontend/src/lib/vpw-tokens.ts
  27 frontend/src/styles/dark-mode.css
 140 frontend/src/styles/finding-detail.css
   3 frontend/src/styles/shadcn-compat.css
  28 frontend/src/styles/tokens.css
```

## Allowlist

- `frontend/src/styles/tokens.css`: canonical CSS token definitions.
- `frontend/src/lib/vpw-tokens.ts` and `frontend/src/lib/vpw-tokens.json`:
  machine-readable token mirrors used by design-system evidence surfaces.
- `frontend/src/components/vpw/VpwDesignSystemShowcase.tsx`: literal token
  swatch labels intentionally display the public VPW palette values.
- `frontend/src/styles/shadcn-compat.css`: compatibility bridge for shadcn and
  Tailwind runtime variables.
- `frontend/src/styles/dark-mode.css`: global dark-mode adapter. It remains a
  dedicated override layer and must not receive route-specific product colors.
- `frontend/src/styles/finding-detail.css`: route-specific detail visualization
  CSS with dense gradient and signal treatment. It is not part of the active
  dashboard/findings/imports/reports screenshot evidence set and remains the
  next tokenization candidate if finding-detail visual redesign is in scope.

## Retired Fallback Selectors

Exact-use search found no mounted consumers for the old fallback selectors
(`side-panel`, `provider-state`, `provider-facts`, `provider-source`,
`panel-header`, `timeline`, `attack-summary-*`). The stylesheet was removed
instead of being kept as an inert palette competitor.
