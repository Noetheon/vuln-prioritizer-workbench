PYTHON ?= python3
MUTMUT ?= $(shell command -v mutmut 2>/dev/null || $(PYTHON) -c 'import os, shutil, site, sysconfig; paths=[sysconfig.get_path("scripts"), os.path.join(site.USER_BASE, "bin")]; print(shutil.which("mutmut") or next((os.path.join(path, "mutmut") for path in paths if os.path.exists(os.path.join(path, "mutmut"))), "mutmut"))')
BACKEND_DIR := backend
BACKEND_TESTS := $(BACKEND_DIR)/tests
MUTATION_PATTERNS := "app.decision_core.builders.x_build_run_diagnostics*" "app.services.report_sarif_validation.x_validate_sarif_file*" "app.domain.engine.services.analysis_quality.x__finding_data_quality_confidence*" "app.domain.engine.services.analysis_snapshot.x__provider_snapshot_hash*" "app.domain.engine.services.analysis_snapshot.x__provider_snapshot_metadata_path*" "app.domain.engine.services.analysis_quality.x_attach_provider_data_quality_flags*"
PYTHON_AUDIT_LOCK := $(BACKEND_DIR)/requirements.lock.txt
PYTHON_RUNTIME_LOCK := $(BACKEND_DIR)/requirements.runtime.lock.txt
COMPOSE := docker compose -f compose.yml -f compose.override.yml
PRODUCTION_SMOKE_COMPOSE := docker compose -f compose.yml -f compose.production-smoke.yml
DOCKER_DEMO_SECRET_KEY ?= local-docker-smoke-secret-key
DOCKER_DEMO_POSTGRES_PASSWORD ?= local-docker-smoke-postgres-password
DOCKER_DEMO_BACKEND_PORT ?= 18080
DOCKER_DEMO_FRONTEND_PORT ?= 15174
PRODUCTION_SMOKE_SECRET_KEY ?= production-smoke-secret-key-change-in-real-deployments
PRODUCTION_SMOKE_POSTGRES_PASSWORD ?= production-smoke-postgres-password
PRODUCTION_SMOKE_FRONTEND_PORT ?= 5180
ACTIONLINT_IMAGE ?= rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
CI_COST_REPORT_LIMIT ?= 20
NPM ?= scripts/frontend-npm.sh
FRONTEND_NPM_ENGINE_STRICT ?= true
FRONTEND_NPM := $(NPM) --prefix frontend --workspaces=false --engine-strict=$(FRONTEND_NPM_ENGINE_STRICT)

.PHONY: install launch workbench-status workbench-stop workbench-reset workbench-update workbench-diagnostics test lint format fix typecheck check critical-coverage-check backend-compatibility-check property-check mutation-check quality-10-check local-workbench-check performance-smoke playwright-install playwright-check playwright-check-without-design-audit frontend-install frontend-build frontend-lint frontend-test-types frontend-test-unit frontend-test-unit-coverage frontend-generate-client api-client-drift-check frontend-design-audit frontend-design-audit-update frontend-design-audit-linux-docker frontend-design-audit-linux-docker-update demo-screenshot frontend-audit frontend-check runtime-assets-sync runtime-assets-check python-lock-check docker-base-image-check pre-commit-pin-check archive-evidence-check public-production-evidence-check release-evidence-hygiene-check docs-check docs-serve actionlint-check workflow-check ci-cost-report docker-demo-smoke docker-production-smoke dependency-audit clean-local clean-deps provider-snapshot-validate package release-bundle package-contents-check package-check package-check-temp release-check release-readiness-check precommit-install

install:
	$(PYTHON) -m pip install -e "$(BACKEND_DIR)[dev]"

launch:
	bash scripts/launch-workbench.sh start

workbench-status:
	bash scripts/launch-workbench.sh status

workbench-stop:
	bash scripts/launch-workbench.sh stop

workbench-reset:
	bash scripts/launch-workbench.sh reset

workbench-update:
	bash scripts/launch-workbench.sh update

workbench-diagnostics:
	bash scripts/launch-workbench.sh diagnostics

test:
	$(PYTHON) -m pytest $(BACKEND_TESTS)

lint:
	$(PYTHON) -m ruff check $(BACKEND_DIR)

format:
	$(PYTHON) -m ruff format $(BACKEND_DIR)

fix:
	$(PYTHON) -m ruff check --fix $(BACKEND_DIR)
	$(PYTHON) -m ruff format $(BACKEND_DIR)

typecheck:
	cd $(BACKEND_DIR) && $(PYTHON) -m mypy app

check:
	$(PYTHON) -m ruff format --check $(BACKEND_DIR)
	$(PYTHON) -m ruff check $(BACKEND_DIR)
	cd $(BACKEND_DIR) && $(PYTHON) -m mypy app
	$(PYTHON) -m pytest $(BACKEND_TESTS)
	mkdir -p build
	$(PYTHON) -m coverage json -o build/coverage-current.json
	$(MAKE) critical-coverage-check

critical-coverage-check:
	$(PYTHON) scripts/check_critical_coverage.py build/coverage-current.json

backend-compatibility-check:
	$(PYTHON) -m pytest -q --no-cov \
		$(BACKEND_TESTS)/test_analysis_inputs.py \
		$(BACKEND_TESTS)/test_input_parser_common.py \
		$(BACKEND_TESTS)/test_input_loader_contracts.py \
		$(BACKEND_TESTS)/test_input_loader_merge.py \
		$(BACKEND_TESTS)/test_grype_json_parser.py \
		$(BACKEND_TESTS)/test_trivy_json_parser.py \
		$(BACKEND_TESTS)/test_github_alerts_normalization.py \
		$(BACKEND_TESTS)/test_backend_runtime_boundary.py \
		$(BACKEND_TESTS)/api/test_workbench_api_skeleton.py \
		$(BACKEND_TESTS)/api/import_contracts/test_import_api_contracts.py \
		$(BACKEND_TESTS)/api/import_contracts/test_import_parser_contracts.py \
		$(BACKEND_TESTS)/api/report_contracts/test_report_format_contracts.py \
		$(BACKEND_TESTS)/api/workflow_contracts/test_durable_workflow_core.py

property-check:
	$(PYTHON) -m pytest -q $(BACKEND_TESTS)/property --no-cov

mutation-check:
	rm -rf .mutmut-cache mutants $(BACKEND_DIR)/.mutmut-cache $(BACKEND_DIR)/mutants
	cd $(BACKEND_DIR) && $(MUTMUT) run --max-children 4 $(MUTATION_PATTERNS)
	cd $(BACKEND_DIR) && $(PYTHON) ../scripts/check_mutmut_results.py mutants $(MUTATION_PATTERNS)
	rm -rf $(BACKEND_DIR)/.mutmut-cache $(BACKEND_DIR)/mutants

local-workbench-check:
	$(MAKE) check
	$(MAKE) docs-check

performance-smoke:
	VPW_PERFORMANCE_SMOKE=1 VPW_PERFORMANCE_SMOKE_OUTPUT=build/vpw-072-performance-smoke.json $(PYTHON) -m pytest -q $(BACKEND_TESTS)/performance/test_vpw072_performance_smoke.py --no-cov

playwright-install: frontend-install
	$(FRONTEND_NPM) exec -- playwright install --with-deps chromium firefox webkit

playwright-check: playwright-install
	$(FRONTEND_NPM) run test

playwright-check-without-design-audit: playwright-install
	$(FRONTEND_NPM) run test -- --grep-invert "design audit matches VPW visual regression baselines"

frontend-install:
	$(FRONTEND_NPM) ci

frontend-build:
	$(FRONTEND_NPM) run build

runtime-assets-sync: frontend-build
	$(PYTHON) scripts/sync_runtime_assets.py

runtime-assets-check:
	$(PYTHON) scripts/sync_runtime_assets.py --check

frontend-lint:
	$(FRONTEND_NPM) run lint

frontend-test-types:
	$(FRONTEND_NPM) run test:types

frontend-test-unit:
	$(FRONTEND_NPM) run test:unit

frontend-test-unit-coverage:
	$(FRONTEND_NPM) run test:unit:coverage

frontend-generate-client:
	bash scripts/generate-client.sh

frontend-design-audit:
	$(FRONTEND_NPM) run test:design-audit

frontend-design-audit-update:
	$(FRONTEND_NPM) run test:design-audit:update

frontend-design-audit-linux-docker:
	bash scripts/frontend-design-audit-linux-docker.sh verify

frontend-design-audit-linux-docker-update:
	bash scripts/frontend-design-audit-linux-docker.sh update

demo-screenshot: playwright-install
	VPW_UPDATE_DOCS_EVIDENCE=1 $(FRONTEND_NPM) run test -- tests/ui-evidence-screenshots.spec.ts --project=chromium

api-client-drift-check:
	before=$$(mktemp); after=$$(mktemp); \
	find frontend/src/client -type f -print | sort | xargs shasum -a 256 > "$$before"; \
	$(MAKE) frontend-generate-client; \
	find frontend/src/client -type f -print | sort | xargs shasum -a 256 > "$$after"; \
	if ! diff -u "$$before" "$$after"; then \
		echo "Generated frontend client changed. Run 'make frontend-generate-client' and commit the result." >&2; \
		git diff -- frontend/src/client; \
		rm -f "$$before" "$$after"; \
		exit 1; \
	fi; \
	rm -f "$$before" "$$after"

frontend-audit:
	$(FRONTEND_NPM) audit --audit-level=high

frontend-check: frontend-install frontend-lint frontend-build runtime-assets-check frontend-test-types frontend-test-unit-coverage api-client-drift-check

release-evidence-hygiene-check:
	$(PYTHON) scripts/check_release_evidence_hygiene.py

archive-evidence-check:
	$(PYTHON) scripts/check_archive_evidence_manifest.py

public-production-evidence-check:
	$(PYTHON) scripts/check_public_deployment_evidence.py

python-lock-check:
	$(PYTHON) scripts/check_release_evidence_hygiene.py

docker-base-image-check:
	$(PYTHON) scripts/check_dockerfile_base_digests.py

pre-commit-pin-check:
	$(PYTHON) scripts/check_pre_commit_pins.py

docs-check: release-evidence-hygiene-check archive-evidence-check
	$(PYTHON) -m mkdocs build --clean

docs-serve:
	$(PYTHON) -m mkdocs serve

provider-snapshot-validate:
	$(PYTHON) -m pytest -q $(BACKEND_TESTS)/test_provider_snapshot_contract.py --no-cov
	$(PYTHON) -c 'import json, jsonschema; from pathlib import Path; schema = json.loads(Path("docs/schemas/provider-snapshot-report.schema.json").read_text(encoding="utf-8")); paths = ("docs/examples/example_provider_snapshot.v1.json", "data/demo_provider_snapshot.json"); [jsonschema.validate(json.loads(Path(path).read_text(encoding="utf-8")), schema) or print(f"{path}: OK") for path in paths]'

actionlint-check:
	docker run --rm -v "$$(pwd):/repo" -w /repo $(ACTIONLINT_IMAGE) -color .github/workflows/*.yml

ci-cost-report:
	$(PYTHON) scripts/ci_cost_report.py --limit $(CI_COST_REPORT_LIMIT)

workflow-check:
	$(MAKE) check
	$(MAKE) docker-base-image-check
	$(PYTHON) scripts/check_github_action_pins.py
	$(MAKE) pre-commit-pin-check
	$(MAKE) docs-check
	$(MAKE) actionlint-check
	$(PYTHON) -m pre_commit run --all-files
	$(MAKE) package-check

docker-demo-smoke:
	@set -e; \
		smoke_id="vpw-demo-smoke-$$(date +%s)-$$$$"; \
		export COMPOSE_PROJECT_NAME="$$smoke_id"; \
		export WORKBENCH_DB_VOLUME="$$smoke_id-db-data"; \
		export WORKBENCH_IMPORT_UPLOADS_VOLUME="$$smoke_id-import-uploads"; \
		export WORKBENCH_REPORTS_VOLUME="$$smoke_id-reports"; \
		export WORKBENCH_PROVIDER_SNAPSHOTS_VOLUME="$$smoke_id-provider-snapshots"; \
		export WORKBENCH_PROVIDER_CACHE_VOLUME="$$smoke_id-provider-cache"; \
	export SECRET_KEY="$(DOCKER_DEMO_SECRET_KEY)"; \
	export POSTGRES_PASSWORD="$(DOCKER_DEMO_POSTGRES_PASSWORD)"; \
	export DOCKER_DEMO_BACKEND_PORT="$(DOCKER_DEMO_BACKEND_PORT)"; \
	export DOCKER_DEMO_FRONTEND_PORT="$(DOCKER_DEMO_FRONTEND_PORT)"; \
	export FRONTEND_HOST="http://localhost:$$DOCKER_DEMO_FRONTEND_PORT"; \
	export BACKEND_CORS_ORIGINS="http://localhost,http://localhost:$$DOCKER_DEMO_FRONTEND_PORT,http://127.0.0.1:$$DOCKER_DEMO_FRONTEND_PORT"; \
	for port in "$$DOCKER_DEMO_BACKEND_PORT" "$$DOCKER_DEMO_FRONTEND_PORT"; do \
		if ! $(PYTHON) -c "import socket, sys; port=int(sys.argv[1]); sock=socket.socket(); sock.settimeout(0.2); in_use=sock.connect_ex(('127.0.0.1', port)) == 0; sock.close(); sys.exit(1 if in_use else 0)" "$$port"; then \
			echo "Port $$port is already in use before docker-demo-smoke." >&2; \
			exit 1; \
		fi; \
	done; \
	on_exit() { status=$$?; if [ "$$status" != "0" ]; then $(COMPOSE) ps || true; $(COMPOSE) logs --no-color || true; fi; $(COMPOSE) down -v --remove-orphans; exit "$$status"; }; \
	trap on_exit EXIT; \
	bash scripts/docker_compose_pull_with_retry.sh -f compose.yml -f compose.override.yml -- db; \
	$(COMPOSE) up -d --build backend frontend worker; \
	backend_ready=0; \
		for attempt in $$(seq 1 30); do \
			if $(PYTHON) -c "import json, sys, urllib.request; port=sys.argv[1]; data=json.load(urllib.request.urlopen(f'http://127.0.0.1:{port}/api/v1/utils/health-check/', timeout=2)); assert data is True; print(data)" "$$DOCKER_DEMO_BACKEND_PORT" 2>/dev/null; then \
				backend_ready=1; \
				break; \
			fi; \
		sleep 2; \
	done; \
	if [ "$$backend_ready" != "1" ]; then \
		echo "Workbench backend health check failed." >&2; \
		exit 1; \
	fi; \
	if ! $(PYTHON) -c "import sys, urllib.request; port=sys.argv[1]; print(urllib.request.urlopen(f'http://127.0.0.1:{port}/api/v1/utils/health-check/', timeout=2).read().decode())" "$$DOCKER_DEMO_BACKEND_PORT" 2>/dev/null; then \
		echo "Workbench utility health check failed." >&2; \
		exit 1; \
	fi; \
	$(COMPOSE) exec -T backend python -m app.core.schema_smoke; \
	frontend_ready=0; \
	for attempt in $$(seq 1 30); do \
		if $(PYTHON) -c "import sys, urllib.request; port=sys.argv[1]; print(urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=2).status)" "$$DOCKER_DEMO_FRONTEND_PORT" 2>/dev/null; then \
			frontend_ready=1; \
			break; \
		fi; \
		sleep 2; \
	done; \
	if [ "$$frontend_ready" != "1" ]; then \
		echo "Workbench frontend health check failed." >&2; \
		exit 1; \
	fi; \
	if ! $(PYTHON) -c "import sys, urllib.request; port=sys.argv[1]; print(urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=2).status)" "$$DOCKER_DEMO_FRONTEND_PORT" 2>/dev/null; then \
		echo "Workbench frontend root route check failed." >&2; \
		exit 1; \
	fi; \
	DOCKER_QUICKSTART_API_BASE_URL="http://127.0.0.1:$$DOCKER_DEMO_BACKEND_PORT/api/v1" $(PYTHON) scripts/docker_quickstart_api_smoke.py; \
	echo "Workbench Docker smoke passed."

docker-production-smoke:
	@set -e; \
		smoke_id="vpw-production-smoke-$$(date +%s)-$$$$"; \
		export COMPOSE_PROJECT_NAME="$$smoke_id"; \
		export WORKBENCH_DB_VOLUME="$$smoke_id-db-data"; \
		export WORKBENCH_IMPORT_UPLOADS_VOLUME="$$smoke_id-import-uploads"; \
		export WORKBENCH_REPORTS_VOLUME="$$smoke_id-reports"; \
		export WORKBENCH_PROVIDER_SNAPSHOTS_VOLUME="$$smoke_id-provider-snapshots"; \
		export WORKBENCH_PROVIDER_CACHE_VOLUME="$$smoke_id-provider-cache"; \
	export SECRET_KEY="$(PRODUCTION_SMOKE_SECRET_KEY)"; \
	export POSTGRES_PASSWORD="$(PRODUCTION_SMOKE_POSTGRES_PASSWORD)"; \
	export PRODUCTION_SMOKE_FRONTEND_PORT="$(PRODUCTION_SMOKE_FRONTEND_PORT)"; \
	$(PYTHON) -c "import socket, sys; port=int(sys.argv[1]); sock=socket.socket(); sock.settimeout(0.2); in_use=sock.connect_ex(('127.0.0.1', port)) == 0; sock.close(); sys.exit(f'Port {port} is already in use before docker-production-smoke.' if in_use else 0)" "$$PRODUCTION_SMOKE_FRONTEND_PORT"; \
	on_exit() { status=$$?; if [ "$$status" != "0" ]; then $(PRODUCTION_SMOKE_COMPOSE) ps || true; $(PRODUCTION_SMOKE_COMPOSE) logs --no-color || true; fi; $(PRODUCTION_SMOKE_COMPOSE) down -v --remove-orphans; exit "$$status"; }; \
	trap on_exit EXIT; \
	bash scripts/docker_compose_pull_with_retry.sh -f compose.yml -f compose.production-smoke.yml -- db; \
	$(PRODUCTION_SMOKE_COMPOSE) up -d --build backend frontend worker; \
	frontend_ready=0; \
	for attempt in $$(seq 1 45); do \
		if $(PYTHON) -c "import sys, urllib.request; port=sys.argv[1]; req=urllib.request.Request(f'http://127.0.0.1:{port}/', headers={'Host': 'workbench.example.test'}); print(urllib.request.urlopen(req, timeout=2).status)" "$$PRODUCTION_SMOKE_FRONTEND_PORT" 2>/dev/null; then \
			frontend_ready=1; \
			break; \
		fi; \
		sleep 2; \
	done; \
	if [ "$$frontend_ready" != "1" ]; then \
		echo "Production-like Workbench frontend did not become ready." >&2; \
		exit 1; \
	fi; \
	$(PRODUCTION_SMOKE_COMPOSE) exec -T backend python -m app.core.schema_smoke; \
	VPW_PRODUCTION_SMOKE_BASE_URL="http://127.0.0.1:$$PRODUCTION_SMOKE_FRONTEND_PORT" $(PYTHON) scripts/production_readiness_smoke.py; \
	echo "Workbench production-like Docker smoke passed."

dependency-audit: python-lock-check docker-base-image-check
	@$(PYTHON) -c "import pip_audit" >/dev/null 2>&1 || { \
		echo "Install pip-audit first: python3 -m pip install pip-audit" >&2; \
		exit 1; \
	}
	$(PYTHON) -m pip_audit --requirement $(PYTHON_AUDIT_LOCK) --require-hashes --disable-pip
	$(MAKE) frontend-audit

clean-local:
	find . -name .DS_Store -not -path './.git/*' -delete
	rm -rf .cache .hypothesis .mypy_cache .pytest_cache .ruff_cache .playwright-cli .playwright-mcp
	rm -rf backend/.mypy_cache backend/.pytest_cache backend/.ruff_cache
	rm -rf backend/*.egg-info
	rm -rf build dist diagnostics site htmlcov test-results frontend/test-results frontend/playwright-report frontend/dist
	rm -rf .coverage .coverage.* backend/.coverage backend/.coverage.* coverage.xml backend-uvicorn.log frontend-vite.log
	rm -rf frontend/openapi.json frontend/screenshot*.mjs
	find . -name __pycache__ -type d -not -path './.git/*' -prune -exec rm -rf {} +
	find . -name '*.py[co]' -not -path './.git/*' -delete

clean-deps: clean-local
	rm -rf node_modules frontend/node_modules Library/Caches/ms-playwright

package: frontend-install runtime-assets-sync
	rm -rf dist
	$(PYTHON) -m build $(BACKEND_DIR) --outdir dist

release-bundle:
	$(PYTHON) scripts/build_release_bundle.py --output dist

package-contents-check: package
	$(PYTHON) scripts/check_package_contents.py dist

package-check: package-contents-check
	$(PYTHON) -m twine check dist/*
	tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	$(PYTHON) -m venv "$$tmp/venv"; \
	"$$tmp/venv/bin/python" -m pip install --upgrade pip >/dev/null; \
	"$$tmp/venv/bin/python" -m pip install --force-reinstall dist/*.whl >/dev/null; \
	"$$tmp/venv/bin/vpw" --version; \
	"$$tmp/venv/bin/python" scripts/workbench_wheel_smoke.py build/package-workbench-wheel-smoke.json

package-check-temp:
	@set -e; \
	tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	rsync -a --exclude .git --exclude .venv --exclude .cache --exclude Library --exclude node_modules --exclude dist --exclude build --exclude site --exclude .mypy_cache --exclude .pytest_cache --exclude .ruff_cache . "$$tmp"/; \
	$(MAKE) -C "$$tmp" package-check

release-check:
	$(MAKE) workflow-check
	$(MAKE) frontend-check
	$(MAKE) dependency-audit
	$(MAKE) docker-demo-smoke

release-readiness-check: release-check api-client-drift-check archive-evidence-check frontend-design-audit-linux-docker playwright-check-without-design-audit docker-production-smoke

quality-10-check:
	$(MAKE) release-readiness-check
	$(MAKE) performance-smoke
	$(MAKE) mutation-check

precommit-install:
	pre-commit install
