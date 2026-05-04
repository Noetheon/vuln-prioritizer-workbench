# VPW-075 Docker Compose Quickstart

VPW-075 validates that a fresh repository checkout can start the template
backend, React frontend, and database with Docker Compose, then complete a
local login and demo import without live provider API keys.

## Scope

- Compose backend runtime directories are writable even though the container is
  read-only by default.
- The Compose backend mounts `./data` read-only and uses it as
  `PROVIDER_SNAPSHOT_DIR`, so `demo_provider_snapshot.json` is available for
  locked replay.
- The local override initializes the template SQLModel tables and configured
  superuser before starting Uvicorn.
- The backend allows the local `127.0.0.1:5173` browser origin used by the
  documented quickstart.
- `make docker-demo-smoke` now verifies login, project creation, locked
  provider snapshot import, and non-empty findings through
  `scripts/docker_quickstart_api_smoke.py`.
- README and docs quickstarts document `.env` setup, local URLs, login defaults,
  locked snapshot import, and the current Adminer/Mailcatcher status.

## Clean Environment Procedure

Run from a fresh checkout or temporary copy:

```bash
cp .env.example .env
docker compose -f compose.yml -f compose.override.yml down -v --remove-orphans
docker compose -f compose.yml -f compose.override.yml up -d --build backend frontend
curl --fail http://127.0.0.1:8000/api/v1/workbench/status
curl --fail http://127.0.0.1:8000/api/v1/utils/health-check/
curl --fail http://127.0.0.1:5173/
curl --fail http://127.0.0.1:5173/login
python3 scripts/docker_quickstart_api_smoke.py
```

Then sign in at `http://127.0.0.1:5173/login` with
`admin@example.com` / `changethis`, create a project, and import
`data/sample_cves.txt` with:

- input type: `CVE list`
- provider snapshot: `demo_provider_snapshot.json`
- locked provider data: enabled

## Terminal Evidence

Representative expected output:

```text
{"status":"ok","app":"Vuln Prioritizer Workbench","core_package":"vuln_prioritizer","core_version":"1.1.0","legacy_api_prefix":"/api","migration":{"phase":"template-backend-adapter","legacy_workbench_mounted":false}}
true
200
200
Template Workbench demo import passed: project_id=<uuid> run_id=<uuid> findings=4 locked_provider_data=True
Template Workbench Docker smoke passed.
```

The API demo import should return an `analysis_run` payload with `status` set to
`succeeded`, non-zero finding counts, `provider_snapshot_file` pointing at
`/app/examples/demo_provider_snapshot.json`, and `locked_provider_data` set to
`true`.

## Screenshot Evidence

The VPW-075 browser evidence captures the Docker Compose frontend after the
locked snapshot import:

- `docs/evidence/vpw-075-dashboard.png`
- `docs/evidence/vpw-075-findings.png`

## Validation Plan

```bash
python3 -m pytest -q backend/tests/test_workbench_integration_contracts.py --no-cov
python3 scripts/docker_quickstart_api_smoke.py
make docker-demo-smoke
make demo-offline-no-key-proof
make docs-check
```

## Validation Results

- `git rev-parse HEAD`: `7b3b30733847d849d7030e0d2bf3fc90fef3356f`
  before the VPW-075 branch commit.
- `docker --version`: Docker version 29.4.0, build 9d7ad9ff18.
- `docker compose version`: Docker Compose version 5.1.2.
- `docker compose -f compose.yml -f compose.override.yml config`: passed.
- `python3 -m py_compile scripts/docker_quickstart_api_smoke.py`: passed.
- `python3 -m pytest -q backend/tests/test_workbench_integration_contracts.py --no-cov`:
  5 passed.
- `make docker-demo-smoke`: passed after building backend/frontend images,
  starting `db`, `backend`, and `frontend`, polling status routes, logging in,
  creating a project, importing `data/sample_cves.txt` with
  `demo_provider_snapshot.json`, and confirming 4 findings with locked provider
  data.
- Docker Compose screenshot capture: passed; dashboard and findings screenshots
  were captured from the Compose-served frontend after the locked snapshot
  import.
- `make demo-offline-no-key-proof`: passed; generated
  `build/vpw-029-demo-offline-no-key-proof.json` with
  `locked_provider_data=true` and `network_fetches=0` for every provider.
- `make docs-check`: passed. MkDocs still reports the pre-existing unnaved page
  `docs/architecture/vpw-011-api-skeleton.md`.
- `make check`: passed; Ruff format, Ruff lint, mypy, and backend pytest
  completed with 839 passed, 6 skipped, and 90.69% coverage.
- `git diff --check`: passed.

## Known Issues

- The local Compose stack is for a single workstation or trusted local network
  only. It is not a public internet deployment.
- Adminer and Mailcatcher/Mailpit are not enabled in the current Compose stack.
  SMTP variables remain placeholders for template parity.
- The quickstart intentionally uses the demo provider snapshot; live provider
  refreshes remain optional and can depend on upstream availability and local
  API keys.
