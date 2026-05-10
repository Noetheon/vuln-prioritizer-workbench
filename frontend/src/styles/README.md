# Frontend CSS Ownership

`frontend/src/index.css` owns the stylesheet import order. Keep broad layers in
this sequence:

1. Tailwind and animation runtime imports.
2. `tokens.css` for VPW design tokens.
3. `layout-tokens.css` for shared layout sizing variables.
4. `vpw-components.css` for reusable VPW component classes.
5. `base.css` for element-level application defaults.
6. Domain styles such as `dashboard.css`, `findings.css`, and focused
   finding-detail slices.
7. Route-specific utilities such as `login.css`.
8. Global overrides in `responsive.css` and `accessibility.css`.

Ownership rules:

- VPW components should get reusable product styling from
  `vpw-components.css` and token values from `tokens.css`.
- Domain CSS files own route or feature-specific classes that are not reusable
  product primitives.
- Finding detail CSS must stay split by product surface:
  `finding-detail-decision.css`, `finding-detail-evidence.css`, and
  `finding-detail-ttp-history.css`. Do not reintroduce a single
  `finding-detail.css` catch-all.
- The old `workbench-fallback.css` compatibility layer was retired after the
  VPW-AUD-206 exact-use scan found no mounted selectors. New legacy fallback
  layers require a tracked owner, an expiry condition, and a color-scan
  allowlist update.
- shadcn semantic utilities are generated from `tokens.css` via Tailwind v4
  `@theme inline`; do not reintroduce a compatibility utility layer.
- `responsive.css` and `accessibility.css` may override earlier layers only
  for their named global concern. Dark mode must be token-driven from
  `tokens.css`, not global element selectors.
