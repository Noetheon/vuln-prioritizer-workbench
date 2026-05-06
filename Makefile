PYTHON ?= python3
BACKEND_DIR := backend
BACKEND_SRC := $(BACKEND_DIR)/src
BACKEND_TESTS := $(BACKEND_DIR)/tests
COMPOSE := docker compose -f compose.yml -f compose.override.yml

ATTACK_MAPPING_FILE := data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json
ATTACK_METADATA_FILE := data/attack/attack_techniques_enterprise_16.1_subset.json
DEMO_FIXED_NOW := 2026-04-21T12:00:00+00:00
DEMO_ENV := PYTHONPATH=$(BACKEND_SRC) VULN_PRIORITIZER_FIXED_NOW=$(DEMO_FIXED_NOW)
DEMO_PROVIDER_SNAPSHOT_FILE := data/demo_provider_snapshot.json
DEMO_PROVIDER_FLAGS := --provider-snapshot-file $(DEMO_PROVIDER_SNAPSHOT_FILE) --locked-provider-data
DEMO_EVIDENCE_ANALYSIS_FILE := build/v1.0-demo-analysis.json
DEMO_EVIDENCE_BUNDLE_FILE := build/v1.0-demo-evidence-bundle.zip
DEMO_EVIDENCE_VERIFICATION_FILE := build/v1.0-demo-evidence-bundle-verification.json

.PHONY: install test lint format fix typecheck check benchmark-check performance-smoke playwright-install playwright-check frontend-install frontend-build frontend-lint frontend-test-unit frontend-generate-client api-client-drift-check frontend-audit frontend-check docs-check docs-serve actionlint-check workflow-check docker-demo-smoke dependency-audit clean-local clean-deps provider-snapshot-validate provider-testmatrix demo-offline-no-key-proof demo-sync-check demo-sync-check-temp package package-contents-check package-check package-check-temp pipx-source-smoke release-check release-readiness-check demo-report demo-compare demo-explain demo-attack-report demo-attack-compare demo-attack-explain demo-attack-coverage demo-attack-navigator demo-pr-comment demo-results-sarif demo-html-report demo-evidence-analysis demo-evidence-bundle demo-evidence-bundle-check precommit-install

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

benchmark-check:
	$(PYTHON) -m pytest -q $(BACKEND_TESTS)/test_benchmark_regressions.py $(BACKEND_TESTS)/test_snapshot_diff_regressions.py $(BACKEND_TESTS)/test_rollup_regressions.py --no-cov

performance-smoke:
	VPW_PERFORMANCE_SMOKE=1 VPW_PERFORMANCE_SMOKE_OUTPUT=build/vpw-072-performance-smoke.json $(PYTHON) -m pytest -q $(BACKEND_TESTS)/performance/test_vpw072_performance_smoke.py --no-cov

playwright-install: frontend-install
	cd frontend && npm --workspaces=false exec playwright install chromium

playwright-check: frontend-install
	cd frontend && npm run test -- tests/ui-smoke.spec.ts tests/responsive-shell.spec.ts

frontend-install:
	cd frontend && npm ci --workspaces=false

frontend-build:
	cd frontend && npm run build

frontend-lint:
	cd frontend && npm run lint

frontend-test-unit:
	cd frontend && npm run test:unit

frontend-generate-client:
	bash scripts/generate-client.sh

api-client-drift-check: frontend-generate-client
	git diff --exit-code -- frontend/src/client

frontend-audit:
	cd frontend && npm --workspaces=false audit --omit=dev

frontend-check: frontend-install frontend-lint frontend-build frontend-test-unit frontend-generate-client

docs-check:
	$(PYTHON) -m mkdocs build --clean

docs-serve:
	$(PYTHON) -m mkdocs serve

provider-snapshot-validate:
	$(PYTHON) -m pytest -q $(BACKEND_TESTS)/test_output_schemas.py::test_provider_snapshot_v1_example_matches_schema_and_model $(BACKEND_TESTS)/test_output_schemas.py::test_demo_provider_snapshot_matches_schema_and_model $(BACKEND_TESTS)/test_provider_snapshot_contract.py --no-cov
	$(PYTHON) -c 'import json, jsonschema; from pathlib import Path; schema = json.loads(Path("docs/schemas/provider-snapshot-report.schema.json").read_text(encoding="utf-8")); paths = ("docs/examples/example_provider_snapshot.v1.json", "data/demo_provider_snapshot.json"); [jsonschema.validate(json.loads(Path(path).read_text(encoding="utf-8")), schema) or print(f"{path}: OK") for path in paths]'

provider-testmatrix:
	$(PYTHON) -m pytest -q $(BACKEND_TESTS)/test_provider_response_contracts.py $(BACKEND_TESTS)/test_provider_contract.py $(BACKEND_TESTS)/test_provider_snapshot_contract.py $(BACKEND_TESTS)/test_cli_data.py::test_data_export_provider_snapshot_cache_only_uses_local_cache $(BACKEND_TESTS)/test_output_schemas.py::test_demo_provider_snapshot_matches_schema_and_model $(BACKEND_TESTS)/api/test_template_import_upload_api.py::test_template_import_uses_demo_snapshot_without_network_or_keys $(BACKEND_TESTS)/test_evidence_bundle_verification.py --no-cov

demo-offline-no-key-proof:
	mkdir -p build
	env -u NVD_API_KEY HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9 $(DEMO_ENV) $(PYTHON) -m vuln_prioritizer.cli analyze --input data/sample_cves.txt --output build/vpw-029-demo-offline-no-key-proof.json --format json $(DEMO_PROVIDER_FLAGS)
	$(PYTHON) -c 'import json; from pathlib import Path; payload = json.loads(Path("build/vpw-029-demo-offline-no-key-proof.json").read_text(encoding="utf-8")); diagnostics = payload["metadata"]["provider_diagnostics"]; assert payload["metadata"]["provider_snapshot_file"] == "data/demo_provider_snapshot.json"; assert payload["metadata"]["locked_provider_data"] is True; assert all(item.get("network_fetches", 0) == 0 for item in diagnostics.values()); print("build/vpw-029-demo-offline-no-key-proof.json: OK")'

actionlint-check:
	docker run --rm -v "$$(pwd):/repo" -w /repo rhysd/actionlint:1.7.12 -color .github/workflows/*.yml .github/examples/*.yml

workflow-check:
	$(MAKE) check
	$(MAKE) docs-check
	$(MAKE) actionlint-check
	$(PYTHON) -m pre_commit run --all-files
	$(MAKE) package-check

docker-demo-smoke:
	@set -e; \
	$(COMPOSE) up -d --build backend frontend; \
	trap '$(COMPOSE) down -v --remove-orphans' EXIT; \
	backend_ready=0; \
	for attempt in $$(seq 1 30); do \
		if $(PYTHON) -c "import json, urllib.request; data=json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/v1/workbench/status', timeout=2)); assert data['database_status'] == 'ready' and data['schema_status'] == 'ready'; print(data)" 2>/dev/null; then \
			backend_ready=1; \
			break; \
		fi; \
		sleep 2; \
	done; \
	if [ "$$backend_ready" != "1" ]; then \
		echo "Workbench backend health check failed." >&2; \
		exit 1; \
	fi; \
	if ! $(PYTHON) -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/api/v1/utils/health-check/', timeout=2).read().decode())" 2>/dev/null; then \
		echo "Workbench utility health check failed." >&2; \
		exit 1; \
	fi; \
	frontend_ready=0; \
	for attempt in $$(seq 1 30); do \
		if $(PYTHON) -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:5173/', timeout=2).status)" 2>/dev/null; then \
			frontend_ready=1; \
			break; \
		fi; \
		sleep 2; \
	done; \
	if [ "$$frontend_ready" != "1" ]; then \
		echo "Workbench frontend health check failed." >&2; \
		exit 1; \
	fi; \
	if ! $(PYTHON) -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:5173/login', timeout=2).status)" 2>/dev/null; then \
		echo "Workbench login route check failed." >&2; \
		exit 1; \
	fi; \
	$(PYTHON) scripts/docker_quickstart_api_smoke.py; \
	echo "Workbench Docker smoke passed."

dependency-audit:
	@$(PYTHON) -c "import pip_audit" >/dev/null 2>&1 || { \
		echo "Install pip-audit first: python3 -m pip install pip-audit" >&2; \
		exit 1; \
	}
	$(PYTHON) -m pip_audit --requirement $(BACKEND_DIR)/requirements.txt
	$(MAKE) frontend-audit

clean-local:
	find . -name .DS_Store -not -path './.git/*' -delete
	rm -rf .cache .mypy_cache .pytest_cache .ruff_cache .playwright-cli .playwright-mcp
	rm -rf backend/.mypy_cache backend/.pytest_cache backend/.ruff_cache
	rm -rf build dist site htmlcov test-results frontend/test-results frontend/playwright-report frontend/dist
	rm -rf .coverage .coverage.* coverage.xml backend-uvicorn.log frontend-vite.log
	find . -name __pycache__ -type d -not -path './.git/*' -prune -exec rm -rf {} +
	find . -name '*.py[co]' -not -path './.git/*' -delete

clean-deps: clean-local
	rm -rf node_modules frontend/node_modules Library/Caches/ms-playwright

demo-sync-check:
	@before="$$(mktemp)"; after="$$(mktemp)"; \
	git diff --binary -- docs > "$$before"; \
	$(MAKE) demo-pr-comment; \
	$(MAKE) demo-results-sarif; \
	$(MAKE) demo-html-report; \
	$(MAKE) demo-report; \
	$(MAKE) demo-compare; \
	$(MAKE) demo-explain; \
	$(MAKE) demo-attack-report; \
	$(MAKE) demo-attack-compare; \
	$(MAKE) demo-attack-explain; \
	$(MAKE) demo-attack-coverage; \
	$(MAKE) demo-attack-navigator; \
	$(MAKE) docs-check; \
	git diff --binary -- docs > "$$after"; \
	if ! cmp -s "$$before" "$$after"; then \
		echo "Checked-in docs/example artifacts are out of sync. Regenerate them and commit the result." >&2; \
		rm -f "$$before" "$$after"; \
		exit 1; \
	fi; \
	rm -f "$$before" "$$after"

demo-sync-check-temp:
	@set -e; \
	tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	rsync -a --exclude .git --exclude .venv --exclude .cache --exclude Library --exclude node_modules --exclude dist --exclude build --exclude site --exclude .mypy_cache --exclude .pytest_cache --exclude .ruff_cache . "$$tmp"/; \
	git -C "$$tmp" init -q; \
	git -C "$$tmp" add docs; \
	git -C "$$tmp" -c user.email=codex@example.invalid -c user.name=Codex commit -q -m baseline-docs -- docs; \
	$(MAKE) -C "$$tmp" demo-sync-check

package:
	rm -rf dist
	$(PYTHON) -m build $(BACKEND_DIR) --outdir dist

package-contents-check: package
	$(PYTHON) scripts/check_package_contents.py dist

package-check: package-contents-check
	$(PYTHON) -m twine check dist/*

package-check-temp:
	@set -e; \
	tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	rsync -a --exclude .git --exclude .venv --exclude .cache --exclude Library --exclude node_modules --exclude dist --exclude build --exclude site --exclude .mypy_cache --exclude .pytest_cache --exclude .ruff_cache . "$$tmp"/; \
	$(MAKE) -C "$$tmp" package-check

pipx-source-smoke:
	$(PYTHON) -m pip install --upgrade pip pipx
	PYTHON_BIN=$(PYTHON) bash scripts/p1_pipx_source_smoke.sh

release-check:
	$(MAKE) workflow-check
	$(MAKE) frontend-check
	$(MAKE) dependency-audit
	$(MAKE) docker-demo-smoke
	$(MAKE) pipx-source-smoke
	$(MAKE) demo-sync-check

release-readiness-check: release-check api-client-drift-check demo-evidence-bundle-check playwright-check

demo-report:
	$(DEMO_ENV) $(PYTHON) -m vuln_prioritizer.cli analyze --input data/sample_cves.txt --output docs/example_report.md --format markdown $(DEMO_PROVIDER_FLAGS)

demo-compare:
	$(DEMO_ENV) $(PYTHON) -m vuln_prioritizer.cli compare --input data/sample_cves.txt --output docs/example_compare.md --format markdown $(DEMO_PROVIDER_FLAGS)

demo-explain:
	$(DEMO_ENV) $(PYTHON) -m vuln_prioritizer.cli explain --cve CVE-2021-44228 --output docs/example_explain.json --format json --offline-attack-file data/optional_attack_to_cve.csv $(DEMO_PROVIDER_FLAGS)

demo-attack-report:
	$(DEMO_ENV) $(PYTHON) -m vuln_prioritizer.cli analyze --input data/sample_cves_mixed.txt --output docs/example_attack_report.md --format markdown --attack-source ctid-json --attack-mapping-file $(ATTACK_MAPPING_FILE) --attack-technique-metadata-file $(ATTACK_METADATA_FILE) $(DEMO_PROVIDER_FLAGS)

demo-attack-compare:
	$(DEMO_ENV) $(PYTHON) -m vuln_prioritizer.cli compare --input data/sample_cves_mixed.txt --output docs/example_attack_compare.md --format markdown --attack-source ctid-json --attack-mapping-file $(ATTACK_MAPPING_FILE) --attack-technique-metadata-file $(ATTACK_METADATA_FILE) $(DEMO_PROVIDER_FLAGS)

demo-attack-explain:
	$(DEMO_ENV) $(PYTHON) -m vuln_prioritizer.cli explain --cve CVE-2023-34362 --output docs/example_attack_explain.json --format json --attack-source ctid-json --attack-mapping-file $(ATTACK_MAPPING_FILE) --attack-technique-metadata-file $(ATTACK_METADATA_FILE) $(DEMO_PROVIDER_FLAGS)

demo-attack-coverage:
	$(DEMO_ENV) $(PYTHON) -m vuln_prioritizer.cli attack coverage --input data/sample_cves_mixed.txt --output docs/example_attack_coverage.md --format markdown --attack-mapping-file $(ATTACK_MAPPING_FILE) --attack-technique-metadata-file $(ATTACK_METADATA_FILE)

demo-attack-navigator:
	$(DEMO_ENV) $(PYTHON) -m vuln_prioritizer.cli attack navigator-layer --input data/sample_cves_attack.txt --output docs/example_attack_navigator_layer.json --attack-mapping-file $(ATTACK_MAPPING_FILE) --attack-technique-metadata-file $(ATTACK_METADATA_FILE)

demo-pr-comment:
	$(DEMO_ENV) $(PYTHON) -m vuln_prioritizer.cli analyze --input data/input_fixtures/trivy_report.json --input-format trivy-json --asset-context data/input_fixtures/example_asset_context.csv --vex-file data/input_fixtures/openvex_statements.json --policy-profile enterprise --output docs/examples/example_pr_comment.md --format markdown $(DEMO_PROVIDER_FLAGS)

demo-results-sarif:
	$(DEMO_ENV) $(PYTHON) -m vuln_prioritizer.cli analyze --input data/input_fixtures/trivy_report.json --input-format trivy-json --asset-context data/input_fixtures/example_asset_context.csv --vex-file data/input_fixtures/openvex_statements.json --policy-profile enterprise --output docs/examples/example_results.sarif --format sarif $(DEMO_PROVIDER_FLAGS)

demo-html-report:
	mkdir -p build
	$(DEMO_ENV) $(PYTHON) -m vuln_prioritizer.cli analyze --input data/input_fixtures/trivy_report.json --input-format trivy-json --asset-context data/input_fixtures/example_asset_context.csv --vex-file data/input_fixtures/openvex_statements.json --policy-profile enterprise --attack-source ctid-json --attack-mapping-file $(ATTACK_MAPPING_FILE) --attack-technique-metadata-file $(ATTACK_METADATA_FILE) --output build/example_report_analysis.json --format json $(DEMO_PROVIDER_FLAGS)
	$(DEMO_ENV) $(PYTHON) -m vuln_prioritizer.cli report html --input build/example_report_analysis.json --output docs/examples/example_report.html

demo-evidence-analysis:
	mkdir -p build
	$(DEMO_ENV) $(PYTHON) -m vuln_prioritizer.cli analyze --input data/input_fixtures/trivy_report.json --input-format trivy-json --asset-context data/input_fixtures/example_asset_context.csv --vex-file data/input_fixtures/openvex_statements.json --policy-profile enterprise --attack-source ctid-json --attack-mapping-file $(ATTACK_MAPPING_FILE) --attack-technique-metadata-file $(ATTACK_METADATA_FILE) --output $(DEMO_EVIDENCE_ANALYSIS_FILE) --format json $(DEMO_PROVIDER_FLAGS)

demo-evidence-bundle: demo-evidence-analysis
	$(DEMO_ENV) $(PYTHON) -m vuln_prioritizer.cli report evidence-bundle --input $(DEMO_EVIDENCE_ANALYSIS_FILE) --output $(DEMO_EVIDENCE_BUNDLE_FILE)

demo-evidence-bundle-check: demo-evidence-bundle
	$(DEMO_ENV) $(PYTHON) -m vuln_prioritizer.cli report verify-evidence-bundle --input $(DEMO_EVIDENCE_BUNDLE_FILE) --output $(DEMO_EVIDENCE_VERIFICATION_FILE) --format json

precommit-install:
	pre-commit install
