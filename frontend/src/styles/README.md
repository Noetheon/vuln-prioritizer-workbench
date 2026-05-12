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
7. Global overrides in `responsive.css` and `accessibility.css`.

Ownership rules:

- VPW components should get reusable product styling from
  `vpw-components.css` and token values from `tokens.css`.
- Domain CSS files own route or feature-specific classes that are not reusable
  product primitives.
- Finding detail CSS must stay split by product surface:
  `finding-detail-decision.css`, `finding-detail-evidence.css`, and
  `finding-detail-ttp-history.css`. Do not reintroduce a single
  `finding-detail.css` catch-all.
- The old `workbench-fallback.css` layer was retired after the VPW-AUD-206
  exact-use scan found no mounted selectors. New temporary fallback layers
  require a tracked owner, an expiry condition, and a color-scan
  allowlist update.
- shadcn semantic utilities are generated from `tokens.css` via Tailwind v4
  `@theme inline`; do not reintroduce a parallel utility layer.
- `responsive.css` and `accessibility.css` may override earlier layers only
  for their named global concern. Dark mode must be token-driven from
  `tokens.css`, not global element selectors.

Design direction:

- `frontend/DESIGN.md` is the durable VPW Precision Light Analyst designset for
  read/write redesign slices. Treat it as guidance for density, tone, component
  choice, and state language.
- The designset adapts only the `frontend-design-awesome-design-md` references
  selected for VPW: Linear precision, Sentry triage, and HashiCorp enterprise
  infrastructure discipline.
- Keep implementation color, radius, elevation, and dark-mode behavior mapped
  to `tokens.css`. Do not create route-local color constants or parallel token
  ladders while applying the designset.
- Read/write analyst states such as demo, stale provider, waiver review,
  generated, verified, blocked, and failed verification should use existing VPW
  tone classes or component props before adding any new CSS.
