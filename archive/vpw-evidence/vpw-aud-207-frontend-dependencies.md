# VPW-AUD-207 Frontend Dependency Audit

Date: 2026-05-07

## Scope

Issue: VPW-AUD-207

Goal: remove unused direct frontend packages, keep the npm lockfile
consistent, and document intentional dependency-audit false positives.

## Removed Direct Packages

Removed from `frontend/package.json` and `frontend/package-lock.json`:

- `@hookform/resolvers`
- `@radix-ui/react-avatar`
- `@radix-ui/react-checkbox`
- `@radix-ui/react-label`
- `@radix-ui/react-radio-group`
- `@radix-ui/react-scroll-area`
- `@radix-ui/react-separator`
- `@tanstack/react-query-devtools`
- `@tanstack/react-router-devtools`
- `@tanstack/react-table`
- `@tanstack/router-devtools`
- `axios`
- `dotenv`
- `form-data`
- `next-themes`
- `react-error-boundary`
- `react-hook-form`
- `react-icons`
- `sonner`
- `zod`

Moved from runtime dependencies to dev dependencies:

- `@tailwindcss/vite`
- `tailwindcss`

## False Positive Allowlist

`tailwindcss` and `tw-animate-css` are used through CSS package entrypoints:

```text
frontend/src/index.css:1:@import "tailwindcss";
frontend/src/index.css:2:@import "tw-animate-css";
```

Build and generated-client tooling remains intentional:

```text
frontend/vite.config.ts imports @tailwindcss/vite, @tanstack/router-plugin/vite,
@vitejs/plugin-react, and vite.
frontend/openapi-ts.config.ts imports @hey-api/openapi-ts.
```

The generated browser client uses native browser `FormData`; it does not need
the npm `form-data` package:

```text
frontend/src/client/core/bodySerializer.gen.ts uses new FormData().
```

`frontend/.depcheckrc` records the Tailwind CSS allowlist and ignores a local
untracked scratch script named `screenshot-polish.mjs` when present in a
developer checkout.

## Validation

Commands run:

```text
npx --yes depcheck frontend
Result: No depcheck issue

npx --yes depcheck frontend --json
Result summary: dependencies=[], devDependencies=[], missing={}

npm ci --workspaces=false
Result: added 297 packages; audited 298 packages; found 0 vulnerabilities

npm --prefix frontend ls --depth=0
Result summary: no extraneous packages after npm ci; direct tree contains 29
packages.

npm --prefix frontend run lint
Result: checked 212 files; no fixes applied.

npm --prefix frontend run build
Result: production bundle built successfully.

npm --prefix frontend run test:unit
Result: 31 passed.

npm --prefix frontend audit --omit=dev
Result: found 0 vulnerabilities.

python3 -m pytest -q backend/tests/test_docs_hygiene.py --no-cov
Result: 5 passed.

git diff --check
Result: passed.
```

Source/config proof:

```text
rg removed package names in frontend, excluding package.json and package-lock.json
Result: no active imports/usages; only generated string comments for
multipart/form-data and client-axios plus this evidence/README wording.

rg kept tooling packages in frontend/src/index.css, frontend/vite.config.ts,
frontend/openapi-ts.config.ts, frontend/package.json
Result: CSS and config entrypoints found for the kept packages.
```

## Residual Risk

The root `bun.lock` is retained as historical Bun-compatible convenience
metadata. The audited frontend install source remains
`frontend/package-lock.json`, as documented in `docs/dependency-and-package-policy.md`.
