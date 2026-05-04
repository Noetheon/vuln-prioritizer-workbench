# VPW-045 Provider Status Page Evidence

VPW-045 adds a dedicated `/providers` Workbench page for inspecting provider
freshness, snapshot identity, cache state, degraded evidence, and source-level
status for NVD, EPSS, and KEV.

## Scope Verified

- The Providers route renders a real authenticated page instead of the generic
  dashboard fallback.
- Provider cards for NVD, EPSS, and KEV use the generated
  `ProvidersService.readProviderStatus()` client against
  `/api/v1/providers/status`.
- The page shows snapshot mode, snapshot ID, content hash, generated time,
  selected sources, source hashes, cache directory, snapshot directory, last
  sync, cache age, warnings, and last error.
- Source cards show availability, selected state, last sync, cache age, stale
  state when the API marks a source stale, and provider-specific detail text.
- Missing, stale, and failed provider evidence is presented as degraded data
  quality rather than as a successful live refresh.

## Screenshot Evidence

```text
docs/evidence/vpw-045-provider-status.png
```

Screenshot file:

```text
docs/evidence/vpw-045-provider-status.png: PNG image data, 1280 x 1713, 8-bit/color RGB, non-interlaced
```

## API Evidence

`GET /api/v1/providers/status` remains the authoritative template-stack
provider status endpoint. The page does not call the legacy
`/api/providers/status` route.

The endpoint now also populates source-level `stale` and
`cache_age_seconds` fields so the React cards can render degraded source
evidence explicitly.

## E2E Proof

The Playwright smoke:

- logs in through the template login form,
- creates a project and imports CVE data to persist a provider snapshot,
- calls `/api/v1/providers/status` with the template JWT and verifies NVD,
  EPSS, and KEV are present,
- opens `/providers`,
- verifies snapshot mode, cache age, snapshot ID, provider cards, content hash,
  and data-quality text,
- captures the VPW-045 screenshot.

```text
> frontend@0.0.0 test
> playwright test

Running 1 test using 1 worker
  ✓  1 [chromium] › tests/template-login-status.spec.ts:17:1 › template login reaches authenticated Workbench status shell

  1 passed
```

## Verification

```bash
python3 -m ruff format backend/app/api/routes/providers.py backend/tests/api/test_template_provider_status_api.py
python3 -m ruff check backend/app/api/routes/providers.py backend/tests/api/test_template_provider_status_api.py
python3 -m pytest -q backend/tests/api/test_template_provider_status_api.py --no-cov
npm --prefix frontend run lint
npm --prefix frontend run build
npm --prefix frontend run test
make frontend-check
python3 -m mkdocs build --clean
git diff --check
make check
```

Observed results:

```text
backend provider status API tests: 4 passed
frontend lint: passed
frontend build: passed
Playwright provider status smoke: 1 passed
make frontend-check: passed
mkdocs build: passed
git diff --check: passed
make check: 734 passed, 5 skipped, coverage 90.59%
```

## Residual Risk

The page displays provider status and evidence only. Provider refresh/update
job creation remains a later roadmap slice.
