# VPW-043 Finding Detail Evidence

VPW-043 adds a `/findings/{finding_id}` detail route for inspecting one
prioritized finding with source context and decision evidence.

## Scope Verified

- The Findings table CVE cell links to the finding detail route.
- The detail header shows CVE, priority, and lifecycle status.
- Overview cards show EPSS, CVSS, KEV, and asset context; missing EPSS/CVSS
  values render explicit provider-gap text.
- The Why this priority section renders the persisted explanation, matched
  reasons, score, and recommended action.
- The Occurrences table renders the additive API `occurrences` contract with
  source, component, asset, owner/service, severity, and fix context.
- Data Quality Flags show provider snapshot notes and a provider data coverage
  block.
- The Back to Findings link returns to the table route.
- External owner/service text is rendered as React text only. The browser smoke
  seeds `<img>` and `<script>`-like input, verifies it is visible as text, and
  asserts no matching DOM node or `window.__vpwXss` marker is created.

## Screenshot Evidence

The finding detail screenshot is saved at:

```text
docs/evidence/vpw-043-finding-detail.png
```

Screenshot file:

```text
docs/evidence/vpw-043-finding-detail.png: PNG image data, 1280 x 2048, 8-bit/color RGB, non-interlaced
```

## API Evidence

`GET /api/v1/findings/{finding_id}` now returns the additive
`FindingDetailPublic` schema. It preserves the prior `FindingPublic` fields and
adds `occurrences`, where each row includes source/import identifiers,
component/version/PURL, target and asset context, owner/service/exposure, raw
severity, fix versions, and run ID.

The generated OpenAPI client was refreshed with:

```bash
bash scripts/generate-client.sh
```

## E2E Proof

The Playwright smoke:

- logs in through the template login form,
- creates a unique project,
- imports CVE-list data and generic occurrence CSV data,
- opens `/findings`,
- clicks the `CVE-2024-3094` detail link for the occurrence-backed row,
- verifies the header, overview cards, Why this priority, occurrences table,
  data quality/provider coverage, and backlink,
- checks HTML escaping for external owner/service strings,
- captures the screenshot evidence.

```text
> frontend@0.0.0 test
> playwright test

Running 1 test using 1 worker
  ✓  1 [chromium] › tests/template-login-status.spec.ts:17:1 › template login reaches authenticated Workbench status shell

  1 passed
```

## Verification

```bash
python3 -m ruff format --check backend/app/api/routes/findings.py backend/app/models/findings.py backend/app/models/__init__.py backend/tests/api/test_template_workbench_api_skeleton.py
python3 -m ruff check backend/app/api/routes/findings.py backend/app/models/findings.py backend/app/models/__init__.py backend/tests/api/test_template_workbench_api_skeleton.py
python3 -m pytest -q backend/tests/api/test_template_workbench_api_skeleton.py --no-cov
python3 -m pytest -q backend/tests/api/test_template_import_upload_api.py --no-cov
make frontend-check
npm --prefix frontend run test
python3 -m mkdocs build --clean
git diff --check
```

Observed results:

```text
backend ruff format/check on edited files: passed
backend template API skeleton tests: 11 passed
backend import upload API tests: 12 passed
make frontend-check: passed
Playwright finding detail smoke: 1 passed
mkdocs build: passed
git diff --check: passed
```

## Residual Risk

The detail UI still lives in the shared `App.tsx` Workbench shell. A later
component extraction can split Findings table/detail views once the remaining
Workbench frontend roadmap issues are complete.
