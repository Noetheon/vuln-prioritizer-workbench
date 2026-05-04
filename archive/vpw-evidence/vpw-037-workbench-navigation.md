# VPW-037 Workbench Navigation Evidence

VPW-037 removes the remaining frontend template navigation shape and exposes
the Workbench navigation required for the duplicate VPW execution track.

## Scope Verified

- Sidebar navigation shows Dashboard, Projects, Imports, Findings, Assets,
  Providers, Reports, and Settings.
- The navigation entries are TanStack Router links backed by route files under
  `frontend/src/routes/_layout/`.
- Login, authenticated backend status loading, current-user display, Settings
  view, and sign-out continue to work.
- No frontend source or Playwright test file contains dead `Items`,
  `ItemService`, `ItemsService`, or `/items` references.

## Screenshot Evidence

The captured sidebar screenshot is saved at:

```text
docs/evidence/vpw-037-sidebar.png
```

Screenshot command:

```bash
cd frontend && node --input-type=module - <<'NODE'
import { chromium } from '@playwright/test'

const browser = await chromium.launch()
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } })
await page.goto('http://127.0.0.1:5173/login')
await page.getByLabel('Email').fill('admin@example.com')
await page.getByLabel('Password').fill('changethis')
await page.getByRole('button', { name: 'Sign in' }).click()
await page.waitForURL('http://127.0.0.1:5173/')
await page
  .getByRole('navigation', { name: 'Workbench navigation' })
  .getByRole('link', { name: 'Dashboard' })
  .waitFor()
await page.locator('.sidebar').screenshot({
  path: '../docs/evidence/vpw-037-sidebar.png',
})
await browser.close()
NODE
```

Screenshot file:

```text
docs/evidence/vpw-037-sidebar.png: PNG image data, 248 x 1230, 8-bit/color RGB, non-interlaced
```

## Frontend Build Excerpt

```text
> frontend@0.0.0 build
> tsc -p tsconfig.build.json && vite build

vite v7.3.2 building client environment for production...
✓ 1924 modules transformed.
dist/assets/projects-BEHYYWW5.js     0.13 kB │ gzip:  0.13 kB
dist/assets/imports-BEHYYWW5.js      0.13 kB │ gzip:  0.13 kB
dist/assets/findings-BEHYYWW5.js     0.13 kB │ gzip:  0.13 kB
dist/assets/assets-BEHYYWW5.js       0.13 kB │ gzip:  0.13 kB
✓ built in 893ms
```

## Verification

```bash
npm --prefix frontend run lint
npm --prefix frontend run build
rg -n "Items|ItemService|ItemsService|/items" frontend/src frontend/tests
npm --prefix frontend run test
```

Observed results:

```text
frontend lint: passed, 25 files checked
frontend build: passed
dead item import scan: no matches
Playwright login smoke: 1 passed
```

## Residual Risk

The new route shells intentionally reuse the existing Workbench dashboard shell
until later VPW issues add full page-specific tables and forms.
