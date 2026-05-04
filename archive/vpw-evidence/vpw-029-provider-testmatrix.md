# VPW-029 Provider Test Matrix

VPW-029 keeps provider behavior reproducible without live API availability. Required
CI tests use checked-in fixtures, fake sessions, or locked provider snapshots. Live
provider checks are optional and must be enabled explicitly.

## Versioned Fixtures

| Source | Fixture | Contract covered |
| --- | --- | --- |
| NVD | `data/provider_contract_fixtures/v1/nvd_cve_api_2_0_response.json` | CVE API 2.0 response shape, CVSS 4.0 parsing, CWE extraction, reference tags. |
| EPSS | `data/provider_contract_fixtures/v1/epss_first_response.json` | FIRST EPSS response shape, score/date parsing, diagnostics. |
| KEV | `data/provider_contract_fixtures/v1/kev_catalog.json` | CISA KEV catalog shape, alias normalization, offline file loading. |
| Negative | `data/provider_contract_fixtures/v1/invalid/epss_missing_data.json` | Clear fixture failure messages including provider and path. |

## Required Matrix

| Capability | Required proof | Command |
| --- | --- | --- |
| Provider response contracts | NVD, EPSS, and KEV fixture-backed tests parse into provider DTOs. | `python3 -m pytest -q backend/tests/test_provider_response_contracts.py --no-cov` |
| Shared provider adapter | NVD/EPSS/KEV adapter status, snapshot fields, cache flags, and degraded data-quality flags. | `python3 -m pytest -q backend/tests/test_provider_contract.py --no-cov` |
| Snapshot v1 schema | Example and demo provider snapshots validate against the published schema and Pydantic model. | `make provider-snapshot-validate` |
| Cache-only export | `data export-provider-snapshot --cache-only` uses local cache and does not refresh providers. | `python3 -m pytest -q backend/tests/test_cli_data.py::test_data_export_provider_snapshot_cache_only_uses_local_cache --no-cov` |
| Locked replay | Analysis uses `data/demo_provider_snapshot.json` with `--locked-provider-data`. | `make demo-offline-no-key-proof` |
| Workbench demo import | `online-shop-demo` imports with no `NVD_API_KEY` and patched provider fetchers that would fail if live calls were made. | `python3 -m pytest -q backend/tests/api/test_workbench_api.py::test_online_shop_demo_import_uses_demo_snapshot_without_network_or_keys --no-cov` |
| Evidence bundle | Evidence ZIP contains `provider/provider-snapshot.json` and verification metadata. | `python3 -m pytest -q backend/tests/test_evidence_bundle_verification.py --no-cov` |
| Optional live APIs | Real NVD/EPSS/KEV smoke checks are skipped by default. | `VPW_RUN_LIVE_PROVIDER_TESTS=1 python3 -m pytest -q backend/tests/live --no-cov` |

## Offline Demo Snapshot

`data/demo_provider_snapshot.json` is the authoritative locked replay artifact for
the `online-shop-demo` flow. It is an explicit `provider-snapshot.v1.json`
artifact with:

- `metadata.snapshot_id = online-shop-demo-provider-snapshot-2026-04-21`
- `metadata.snapshot_format = provider-snapshot.v1.json`
- `metadata.cache_only = true`
- `metadata.source_metadata` for NVD, EPSS, and KEV

The demo no-key proof writes `build/vpw-029-demo-offline-no-key-proof.json` and
asserts that every provider diagnostic reports `network_fetches = 0`.
