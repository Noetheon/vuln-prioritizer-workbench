# Workbench Offline Demo Runbook

This runbook keeps the Workbench demo reproducible without live provider calls. It uses the checked-in locked provider snapshot and local fixture inputs.

## Scope

- Demonstrates import, prioritization, provider freshness, findings triage, reports, and evidence bundles.
- Uses existing CVE/scanner fixtures; the Workbench does not scan systems or test exploitability.
- Keeps ATT&CK context defensive and optional. Do not present mappings as proof that exploitation occurred.

## Preflight

```bash
make install
python3 -m pytest -q backend/tests/api/test_workbench_api.py backend/tests/web/test_workbench_pages.py --no-cov
make docker-demo-smoke
make docker-postgres-migration-smoke
make dependency-audit
make demo-evidence-bundle-check
docker compose up --build
```

Open `http://127.0.0.1:8000` and create the project `online-shop-demo`.

If `pip-audit` is unavailable or advisory data cannot be reached, record that as a release-checklist exception instead of treating the offline browser demo itself as failed.

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
| Security headers | `tests/api/test_workbench_api.py::test_workbench_health_and_project_crud` and an optional `curl -I http://127.0.0.1:8000/api/health` capture showing `nosniff`, `DENY`, and CSP. |
| Upload filename/path validation | `tests/api/test_workbench_api.py::test_workbench_rejects_unsupported_and_oversized_uploads` plus `test_workbench_rejects_untrusted_provider_snapshot_path`. |
| Report/evidence downloads | `tests/api/test_workbench_api.py::test_workbench_import_findings_reports_and_evidence` and `test_workbench_downloads_reject_tampered_artifact_paths`; browser evidence should show report links and Evidence ZIP verification. |
| 10k findings API smoke | `tests/api/test_workbench_api.py::test_workbench_findings_api_handles_10k_pagination_smoke`. |
| Docker demo smoke | `make docker-demo-smoke` output showing `/api/health` returns `{"status":"ok"}` before teardown. |
| Dependency audit | `make dependency-audit` result, or a documented exception when `pip-audit` or advisory data is unavailable. |
| Demo evidence bundle | `make demo-evidence-bundle-check` output plus `build/v1.0-demo-evidence-bundle-verification.json` showing `ok=true`. |

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
