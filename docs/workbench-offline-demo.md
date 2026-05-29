# Workbench Offline Demo Runbook

This runbook keeps the Workbench demo reproducible without live provider calls.
It uses the checked-in locked provider snapshot and local fixture inputs for the
**Online Shop Demo Workspace** risk operations review.

## Scope

- Demonstrates import, prioritization, provider freshness, findings triage,
  assets, risk acceptance, reports, and evidence bundles.
- Uses existing CVE/scanner fixtures; the Workbench does not scan systems or test exploitability.
- Keeps ATT&CK context defensive and optional. Do not present mappings as proof that exploitation occurred.

## Preflight

```bash
make install
make provider-snapshot-validate
python3 -m pytest -q backend/tests/api/test_workbench_local_runtime_smoke.py backend/tests/api/import_contracts backend/tests/api/report_contracts --no-cov
make docker-demo-smoke
make dependency-audit
docker compose -f compose.yml -f compose.override.yml up --build backend frontend worker
```

Open `http://127.0.0.1:5173` and create the project `online-shop-demo`.
The browser demo uses the active backend in `backend/app` and the generated
`/api/v1` React client. The `worker` service must stay running because imports,
provider refreshes, report generation, retry, and cancellation are durable
Workflow v2 jobs.

The smoke target defaults to backend `18080` and frontend `15174`. If those
host ports are already occupied, run it with explicit host bindings, for
example:

```bash
DOCKER_DEMO_BACKEND_PORT=18081 DOCKER_DEMO_FRONTEND_PORT=15175 make docker-demo-smoke
```

If `pip-audit`, npm, or advisory data is unavailable, record that as a release-checklist exception instead of treating the offline browser demo itself as failed.

## Demo Steps

1. Open the Workbench dashboard.
2. Select **Load demo workspace**. This seeds the deterministic Online Shop
   workspace through normal import and report services.
3. Confirm the dashboard shows 24 findings, high EPSS signals, KEV-backed
   exposure, top services, recent runs, and locked provider replay status.
4. Open **Findings** and apply filters for `Critical`, `High`, `KEV`, owner,
   service, status, and CVE search.
5. Open a mapped critical finding such as Log4Shell and show `Why this
   priority?`, EPSS, CVSS, KEV, component, asset, owner, evidence, and TTP
   context.
6. Open an unmapped XZ finding and show that unmapped CVEs remain unmapped; no
   ATT&CK inference is generated.
7. Open **Assets** and show service, owner, environment, exposure, and linked
   findings.
8. Open **Risk Acceptance** and show active, expiring-soon, and review-due
   accepted-risk records.
9. Open **Providers** and show NVD, EPSS, and KEV status, cache age, snapshot
   mode, and provider data-quality notes. State that locked replay means
   reproducible, not automatically fresh.
10. Open **Evidence Center** and show technical Markdown, Executive HTML,
    analysis JSON, findings CSV, SARIF, ATT&CK Navigator layer, and Evidence ZIP.
11. Download the Evidence ZIP and verify the manifest through the report API.
12. Open **Settings** and confirm local workspace access, runtime health,
    provider status, and diagnostics are visible without exposing secrets.

## Readiness Checks

| Check | Evidence to capture |
| --- | --- |
| Security headers | `tests/api/test_workbench_local_runtime_smoke.py` and an optional `curl -I http://127.0.0.1:8000/api/v1/utils/health-check/` capture showing `nosniff`, `DENY`, and CSP. |
| Upload filename/path validation | `tests/api/import_contracts/` covers active `/api/v1` upload size, suffix, MIME, path, and provider snapshot validation. |
| Report/evidence downloads | `tests/api/report_contracts/`; browser evidence should show report links and Evidence ZIP verification. |
| 10k findings API smoke | `make performance-smoke` runs the active Workbench import and pagination smoke with 10,000 findings. |
| Docker demo smoke | `make docker-demo-smoke` output showing `/api/v1/utils/health-check/` succeeds, the Compose Postgres Alembic/schema/repository smoke passes, and the local import/provider smoke tears down cleanly. |
| Dependency audit | `make dependency-audit` result for the backend Python lock and frontend runtime plus dev/build-chain dependencies, or a documented exception when audit tooling or advisory data is unavailable. |
| Demo evidence bundle | Generate JSON, Markdown, HTML, and Evidence ZIP from the Workbench report page and verify the ZIP through the report API. |
| Provider replay | `make provider-snapshot-validate` plus the Workbench import test showing locked provider snapshot replay without live keys. |

## Updating the Demo Provider Snapshot

Only update `data/demo_provider_snapshot.json` as an intentional release task.
The snapshot must remain a valid explicit `provider-snapshot.v1.json` artifact
and must not depend on reviewer API keys or live provider availability.

1. Refresh `data/demo_provider_snapshot.json` from reviewed provider data in a
   controlled maintainer environment.

2. Re-run the local Workbench validation:

   ```bash
   make provider-snapshot-validate
   python3 -m pytest -q backend/tests/api/import_contracts backend/tests/api/report_contracts --no-cov
   ```

3. Review the snapshot diff before committing. Expected changes are provider
   dates, source hashes, provider records, and generated demo artifact hashes.
   Do not commit secrets, local private paths, or customer scanner exports.

## Screenshot Evidence List

- Setup or project creation page.
- Import form with locked provider snapshot selected.
- Dashboard with priority counts and provider freshness.
- Findings table with filters applied.
- Finding detail showing CVSS, EPSS, KEV, component, asset, owner, rationale, recommended action, and raw evidence.
- Providers page showing NVD, EPSS, KEV status, cache state, and snapshot state.
- Risk Acceptance page showing active, expiring soon, and review-due decisions.
- Settings page showing local workspace, runtime, and provider diagnostics without secret values.
- Reports page showing generated JSON, Markdown, HTML, and Evidence ZIP.
- Downloaded Evidence ZIP verification output.

Checked-in README screenshots from the current offline demo path:

- `docs/examples/media/workbench-dashboard.png`
- `docs/examples/media/workbench-findings.png`
- `docs/examples/media/workbench-finding-detail-ttp.png`
- `docs/examples/media/workbench-risk-acceptance.png`
- `docs/examples/media/workbench-reports-evidence.png`

These screenshots should show the current Online Shop Demo Workspace. Refresh
them intentionally after demo data or primary navigation changes.

## Fallback Artifacts

If the browser demo cannot be shown, use these checked-in or generated artifacts:

- `docs/example_report.md`
- `docs/example_attack_report.md`
- `docs/examples/example_report.html`
- `docs/examples/vpw-054-workbench-technical-report.md`
- `docs/examples/vpw-054-workbench-executive-report.html`
- `docs/examples/vpw-054-workbench-analysis-result.v1.json`
- `docs/examples/example_pr_comment.md`
- `docs/examples/example_results.sarif`
- `data/demo_provider_snapshot.json`
- `build/v1.0-demo-analysis.json`
- `build/v1.0-demo-evidence-bundle.zip`
- `build/v1.0-demo-evidence-bundle-verification.json`

## No-Secret Rules

- Do not show environment variable values.
- Do not show local private paths outside the repository.
- Do not upload customer scanner exports for the public demo.
- Do not show API keys, tokens, cookies, or shell history.

## Residual Gaps to State in Demo Notes

- The Workbench remains local-first and is not ready for internet-exposed or multi-tenant operation.
- Evidence bundles are integrity-checked ZIP artifacts, not encrypted archives.
- SQLite or Postgres backup, retention, volume permissions, and filesystem
  protections remain operator responsibilities.
- Live provider availability is not required for this demo; locked snapshots and local fixtures are the reproducible local demo path.
