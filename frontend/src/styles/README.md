# Frontend CSS Ownership

`frontend/src/index.css` owns the stylesheet import order. Keep broad layers in
this sequence:

1. Tailwind and animation runtime imports.
2. `tokens.css` for VPW design tokens.
3. `shadcn-compat.css` for shadcn primitive compatibility.
4. `layout-tokens.css` for shared layout sizing variables.
5. `vpw-components.css` for reusable VPW component classes.
6. `base.css` for element-level application defaults.
7. Domain styles such as `dashboard.css`, `findings.css`, and
   `finding-detail.css`.
8. Route-specific utilities such as `login.css`.
9. Global overrides in `responsive.css`, `accessibility.css`, then
    `dark-mode.css`.

Ownership rules:

- VPW components should get reusable product styling from
  `vpw-components.css` and token values from `tokens.css`.
- Domain CSS files own route or feature-specific classes that are not reusable
  product primitives.
- The old `workbench-fallback.css` compatibility layer was retired after the
  VPW-AUD-206 exact-use scan found no mounted selectors. New legacy fallback
  layers require a tracked owner, an expiry condition, and a color-scan
  allowlist update.
- `responsive.css`, `accessibility.css`, and `dark-mode.css` may override
  earlier layers only for their named global concern.
