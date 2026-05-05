# Workbench Offline Demo Runbook

This runbook keeps the Workbench demo reproducible without live provider calls. It uses the checked-in locked provider snapshot and local fixture inputs.

## Scope

- Demonstrates import, prioritization, provider freshness, findings triage, reports, and evidence bundles.
- Uses existing CVE/scanner fixtures; the Workbench does not scan systems or test exploitability.
- Keeps ATT&CK context defensive and optional. Do not present mappings as proof that exploitation occurred.

## Preflight

```bash
make install
make provider-snapshot-validate
make provider-testmatrix
make demo-offline-no-key-proof
python3 -m pytest -q backend/tests/api/test_template_auth_smoke.py backend/tests/api/test_template_import_upload_api.py backend/tests/api/test_template_reports_api.py --no-cov
make docker-demo-smoke
make dependency-audit
make demo-evidence-bundle-check
docker compose -f compose.yml -f compose.override.yml up --build backend frontend
```

Open `http://127.0.0.1:5173` and create the project `online-shop-demo`.
The browser demo uses the active backend in `backend/app` and the generated
`/api/v1` React client.

If `pip-audit`, npm, or advisory data is unavailable, record that as a release-checklist exception instead of treating the offline browser demo itself as failed.

## Demo Steps

1. Open **Import**.
2. Select `CVE list`.
3. Upload `data/sample_cves.txt`.
4. Set provider snapshot to `demo_provider_snapshot.json`.
5. Enable locked provider data.
6. Submit the import and open the generated reports page.
7. Return to the dashboard and confirm provider freshness is visible.
8. Open **Findings** and apply filters for `Critical`, `High`, `KEV`, owner, service, and CVE search.
9. Open a critical finding and show `Why this priority?`, EPSS, CVSS, KEV, component, asset, owner, and raw evidence.
10. Open **Intelligence**, search for `CVE-2021-44228`, and show stored provider data plus project findings.
11. Open **Settings** and confirm runtime paths and provider status are visible while secrets are redacted.
12. Create JSON, Markdown, HTML, and Evidence ZIP artifacts from the run page.

## Readiness Checks

| Check | Evidence to capture |
| --- | --- |
| Security headers | `tests/api/test_template_auth_smoke.py` and an optional `curl -I http://127.0.0.1:8000/api/v1/utils/health-check/` capture showing `nosniff`, `DENY`, and CSP. |
| Upload filename/path validation | `tests/api/test_template_import_upload_api.py` covers active `/api/v1` upload size, suffix, MIME, path, and provider snapshot validation. |
| Report/evidence downloads | `tests/api/test_template_reports_api.py`; browser evidence should show report links and Evidence ZIP verification. |
| 10k findings API smoke | `make performance-smoke` runs the active template import and pagination smoke with 10,000 findings. |
| Docker demo smoke | `make docker-demo-smoke` output showing `/api/v1/workbench/status` returns `{"status":"ok"}` before teardown. |
| Dependency audit | `make dependency-audit` result for backend requirements and frontend production dependencies, or a documented exception when audit tooling or advisory data is unavailable. |
| Demo evidence bundle | `make demo-evidence-bundle-check` output plus `build/v1.0-demo-evidence-bundle-verification.json` showing `ok=true`. |
| Provider test matrix | `make provider-testmatrix` plus `archive/vpw-evidence/vpw-029-provider-testmatrix.md`. |
| Offline/no-key proof | `make demo-offline-no-key-proof` output plus `build/vpw-029-demo-offline-no-key-proof.json` showing locked replay and provider `network_fetches=0`. |

## Updating the Demo Provider Snapshot

Only update `data/demo_provider_snapshot.json` as an intentional release task.
The snapshot must remain a valid explicit `provider-snapshot.v1.json` artifact
and must not depend on reviewer API keys or live provider availability.

1. Refresh provider cache from a controlled maintainer environment:

   ```bash
   PYTHONPATH=backend/src python3 -m vuln_prioritizer.cli data update \
     --input data/sample_cves.txt \
     --cache-dir .cache/vuln-prioritizer \
     --offline-kev-file data/input_fixtures/kev_catalog.json
   ```

2. Export the locked replay artifact:

   ```bash
   PYTHONPATH=backend/src python3 -m vuln_prioritizer.cli data export-provider-snapshot \
     --input data/sample_cves.txt \
     --output data/demo_provider_snapshot.json \
     --cache-dir .cache/vuln-prioritizer \
     --cache-only
   ```

3. Re-run the offline proof and generated demo artifacts:

   ```bash
   make provider-snapshot-validate
   make demo-offline-no-key-proof
   make demo-sync-check
   make demo-evidence-bundle-check
   ```

4. Review the snapshot diff before committing. Expected changes are provider
   dates, source hashes, provider records, and generated demo artifact hashes.
   Do not commit secrets, local private paths, or customer scanner exports.

## Screenshot Evidence List

- Setup or project creation page.
- Import form with locked provider snapshot selected.
- Dashboard with priority counts and provider freshness.
- Findings table with filters applied.
- Finding detail showing CVSS, EPSS, KEV, component, asset, owner, rationale, recommended action, and raw evidence.
- Vulnerability Intelligence lookup result.
- Settings page showing `<set>` or `<not set>` instead of secret values.
- Reports page showing generated JSON, Markdown, HTML, and Evidence ZIP.
- Downloaded Evidence ZIP verification output.

Checked-in README screenshots from the current offline demo path:

- `docs/examples/media/workbench-dashboard.png`
- `docs/examples/media/workbench-findings.png`
- `docs/examples/media/workbench-finding-detail-ttp.png`
- `docs/examples/media/workbench-reports-evidence.png`

## Fallback Artifacts

If the browser demo cannot be shown, use these checked-in or generated artifacts:

- `docs/example_report.md`
- `docs/example_compare.md`
- `docs/example_attack_report.md`
- `docs/examples/example_report.html`
- `docs/examples/vpw-054-template-technical-report.md`
- `docs/examples/vpw-054-template-executive-report.html`
- `docs/examples/vpw-054-template-analysis-result.v1.json`
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
- SQLite backup, retention, and filesystem permissions remain operator responsibilities.
- Live provider availability is not required for this demo; locked snapshots and local fixtures are the release-readiness path.
