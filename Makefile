PYTHON ?= python3
BACKEND_DIR := backend
BACKEND_SRC := $(BACKEND_DIR)/src
BACKEND_TESTS := $(BACKEND_DIR)/tests
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

.PHONY: install test lint format fix typecheck check local-workbench-check performance-smoke playwright-install playwright-check frontend-install frontend-build frontend-lint frontend-test-types frontend-test-unit frontend-test-unit-coverage frontend-generate-client api-client-drift-check frontend-audit frontend-check python-lock-check docker-base-image-check archive-evidence-check public-production-evidence-check release-evidence-hygiene-check docs-check docs-serve actionlint-check workflow-check docker-demo-smoke docker-production-smoke dependency-audit clean-local clean-deps provider-snapshot-validate package package-contents-check package-check package-check-temp release-check release-readiness-check precommit-install

install:
	$(PYTHON) -m pip install -e "$(BACKEND_DIR)[dev]"

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
	cd $(BACKEND_DIR) && $(PYTHON) -m mypy app src

check:
	$(PYTHON) -m ruff format --check $(BACKEND_DIR)
	$(PYTHON) -m ruff check $(BACKEND_DIR)
	cd $(BACKEND_DIR) && $(PYTHON) -m mypy app src
	$(PYTHON) -m pytest $(BACKEND_TESTS)

local-workbench-check:
	$(MAKE) check
	$(MAKE) docs-check

performance-smoke:
	VPW_PERFORMANCE_SMOKE=1 VPW_PERFORMANCE_SMOKE_OUTPUT=build/vpw-072-performance-smoke.json $(PYTHON) -m pytest -q $(BACKEND_TESTS)/performance/test_vpw072_performance_smoke.py --no-cov

playwright-install: frontend-install
	cd frontend && npm --workspaces=false exec playwright install --with-deps chromium

playwright-check: playwright-install
	cd frontend && npm run test

frontend-install:
	cd frontend && npm ci --workspaces=false

frontend-build:
	cd frontend && npm run build

frontend-lint:
	cd frontend && npm run lint

frontend-test-types:
	cd frontend && npm run test:types

frontend-test-unit:
	cd frontend && npm run test:unit

frontend-test-unit-coverage:
	cd frontend && npm run test:unit:coverage

frontend-generate-client:
	bash scripts/generate-client.sh

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
	cd frontend && npm --workspaces=false audit --audit-level=high

frontend-check: frontend-install frontend-lint frontend-build frontend-test-types frontend-test-unit-coverage api-client-drift-check

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

docs-check: release-evidence-hygiene-check archive-evidence-check
	$(PYTHON) -m mkdocs build --clean

docs-serve:
	$(PYTHON) -m mkdocs serve

provider-snapshot-validate:
	$(PYTHON) -m pytest -q $(BACKEND_TESTS)/test_provider_snapshot_contract.py --no-cov
	$(PYTHON) -c 'import json, jsonschema; from pathlib import Path; schema = json.loads(Path("docs/schemas/provider-snapshot-report.schema.json").read_text(encoding="utf-8")); paths = ("docs/examples/example_provider_snapshot.v1.json", "data/demo_provider_snapshot.json"); [jsonschema.validate(json.loads(Path(path).read_text(encoding="utf-8")), schema) or print(f"{path}: OK") for path in paths]'

actionlint-check:
	docker run --rm -v "$$(pwd):/repo" -w /repo $(ACTIONLINT_IMAGE) -color .github/workflows/*.yml

workflow-check:
	$(MAKE) check
	$(MAKE) docker-base-image-check
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
	$(COMPOSE) up -d --build backend frontend; \
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
	$(PRODUCTION_SMOKE_COMPOSE) up -d --build backend frontend; \
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
	$(PYTHON) -m pip_audit --requirement $(PYTHON_AUDIT_LOCK)
	$(MAKE) frontend-audit

clean-local:
	find . -name .DS_Store -not -path './.git/*' -delete
	rm -rf .cache .mypy_cache .pytest_cache .ruff_cache .playwright-cli .playwright-mcp
	rm -rf backend/.mypy_cache backend/.pytest_cache backend/.ruff_cache
	rm -rf build dist site htmlcov test-results frontend/test-results frontend/playwright-report frontend/dist
	rm -rf .coverage .coverage.* backend/.coverage backend/.coverage.* coverage.xml backend-uvicorn.log frontend-vite.log
	find . -name __pycache__ -type d -not -path './.git/*' -prune -exec rm -rf {} +
	find . -name '*.py[co]' -not -path './.git/*' -delete

clean-deps: clean-local
	rm -rf node_modules frontend/node_modules Library/Caches/ms-playwright

package:
	rm -rf dist
	$(PYTHON) -m build $(BACKEND_DIR) --outdir dist

package-contents-check: package
	$(PYTHON) scripts/check_package_contents.py dist

package-check: package-contents-check
	$(PYTHON) -m twine check dist/*
	tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	$(PYTHON) -m venv "$$tmp/venv"; \
	"$$tmp/venv/bin/python" -m pip install --upgrade pip >/dev/null; \
	"$$tmp/venv/bin/python" -m pip install --force-reinstall dist/*.whl >/dev/null; \
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

release-readiness-check: release-check api-client-drift-check archive-evidence-check playwright-check docker-production-smoke

precommit-install:
	pre-commit install
