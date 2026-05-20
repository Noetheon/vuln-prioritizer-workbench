# Triage / Findings UI Audit Evidence

Generated: 2026-05-20

## Scope

- `/findings` Triage center
- Quick view drawer from the Findings table
- `/findings/:findingId` detail page
- Detail tabs: Evidence, ATT&CK, History
- Viewports: WQHD `2560x1440`, MacBook `1470x956`, mobile `390x844`

## Evidence

- Screenshots: `screenshots/`
- Metrics: `audit-metrics.json`

## Automated Checks

- Screenshots generated: 17
- Duplicate screenshot hashes: 0
- Browser console errors/warnings during capture: 0
- Horizontal body/document overflow: 0 in all captured states
- Vite/framework overlays: 0
- Drawer bounds:
  - WQHD quick view drawer: `left=1936`, `right=2560`, `width=624`, `viewport=2560`
  - MacBook quick view drawer: `left=846`, `right=1470`, `width=624`, `viewport=1470`
  - Mobile quick view drawer: `left=0`, `right=390`, `width=390`, `viewport=390`

## Critical Audit Notes

- Fixed mobile Finding detail evidence: source occurrences now render as stacked mobile cards instead of a clipped desktop table.
- Fixed evidence summary grid behavior so partial rows do not leave dead grey grid cells.
- Fixed decision reason rows so odd item counts wrap without visual empty cells.
- Fixed MacBook detail layout by stacking the evidence/detail subgrid below `1600px`.
- Stabilized the ATT&CK live E2E spec so it does not reuse a frontend server pointed at the wrong backend.

## Tests Run

- `npm --prefix frontend run lint`
- `npm --prefix frontend run test:types`
- `VPW_PLAYWRIGHT_REUSE_EXISTING_SERVER=1 npm --prefix frontend run test -- findings-route-integration.spec.ts`
- `VPW_PLAYWRIGHT_REUSE_EXISTING_SERVER=1 npm --prefix frontend run test -- responsive-shell.spec.ts`
- `VPW_PLAYWRIGHT_FRONTEND_PORT=15174 npm --prefix frontend run test -- finding-ttp-context.spec.ts`
