PYTHON ?= python3

ATTACK_MAPPING_FILE := data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json
ATTACK_METADATA_FILE := data/attack/attack_techniques_enterprise_16.1_subset.json
DEMO_FIXED_NOW := 2026-04-21T12:00:00+00:00
DEMO_ENV := PYTHONPATH=src VULN_PRIORITIZER_FIXED_NOW=$(DEMO_FIXED_NOW)
DEMO_PROVIDER_SNAPSHOT_FILE := data/demo_provider_snapshot.json
DEMO_PROVIDER_FLAGS := --provider-snapshot-file $(DEMO_PROVIDER_SNAPSHOT_FILE) --locked-provider-data
DEMO_EVIDENCE_ANALYSIS_FILE := build/v1.0-demo-analysis.json
DEMO_EVIDENCE_BUNDLE_FILE := build/v1.0-demo-evidence-bundle.zip
DEMO_EVIDENCE_VERIFICATION_FILE := build/v1.0-demo-evidence-bundle-verification.json

.PHONY: install test lint format fix typecheck check benchmark-check playwright-install playwright-check docs-check docs-serve actionlint-check workflow-check docker-demo-smoke docker-postgres-migration-smoke dependency-audit demo-sync-check demo-sync-check-temp package package-check package-check-temp pipx-source-smoke release-check demo-report demo-compare demo-explain demo-attack-report demo-attack-compare demo-attack-explain demo-attack-coverage demo-attack-navigator demo-pr-comment demo-results-sarif demo-html-report demo-evidence-analysis demo-evidence-bundle demo-evidence-bundle-check precommit-install

install:
	$(PYTHON) -m pip install -e .[dev]

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .

format:
	$(PYTHON) -m ruff format .

fix:
	$(PYTHON) -m ruff check --fix .
	$(PYTHON) -m ruff format .

typecheck:
	$(PYTHON) -m mypy src

check:
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m ruff check .
	$(PYTHON) -m mypy src
	$(PYTHON) -m pytest

benchmark-check:
	$(PYTHON) -m pytest -q tests/test_benchmark_regressions.py tests/test_snapshot_diff_regressions.py tests/test_rollup_regressions.py --no-cov

playwright-install:
	$(PYTHON) -m playwright install chromium

playwright-check:
	VULN_PRIORITIZER_RUN_PLAYWRIGHT=1 $(PYTHON) -m pytest -q tests/playwright --no-cov

docs-check:
	$(PYTHON) -m mkdocs build --clean

docs-serve:
	$(PYTHON) -m mkdocs serve

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
	docker compose up -d --build; \
	trap 'docker compose down -v --remove-orphans' EXIT; \
	for attempt in $$(seq 1 30); do \
		if $(PYTHON) -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2).read().decode())" 2>/dev/null; then \
			exit 0; \
		fi; \
		sleep 2; \
	done; \
	echo "Workbench health check failed." >&2; \
	exit 1

docker-postgres-migration-smoke:
	@set -e; \
	docker compose --profile postgres up -d --build postgres workbench-postgres; \
	trap 'docker compose --profile postgres down -v --remove-orphans' EXIT; \
	for attempt in $$(seq 1 30); do \
		if $(PYTHON) -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8001/api/health', timeout=2).read().decode())" 2>/dev/null; then \
			exit 0; \
		fi; \
		sleep 2; \
	done; \
	echo "Postgres Workbench health check failed." >&2; \
	exit 1

dependency-audit:
	@$(PYTHON) -c "import pip_audit" >/dev/null 2>&1 || { \
		echo "Install pip-audit first: python3 -m pip install pip-audit" >&2; \
		exit 1; \
	}
	$(PYTHON) -m pip_audit --requirement requirements.txt

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
	rsync -a --exclude .git --exclude .venv --exclude .cache --exclude Library --exclude dist --exclude build --exclude site --exclude .mypy_cache --exclude .pytest_cache --exclude .ruff_cache . "$$tmp"/; \
	git -C "$$tmp" init -q; \
	git -C "$$tmp" add docs; \
	git -C "$$tmp" -c user.email=codex@example.invalid -c user.name=Codex commit -q -m baseline-docs -- docs; \
	$(MAKE) -C "$$tmp" demo-sync-check

package:
	rm -rf dist
	$(PYTHON) -m build

package-check: package
	$(PYTHON) -m twine check dist/*

package-check-temp:
	@set -e; \
	tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	rsync -a --exclude .git --exclude .venv --exclude .cache --exclude Library --exclude dist --exclude build --exclude site --exclude .mypy_cache --exclude .pytest_cache --exclude .ruff_cache . "$$tmp"/; \
	$(MAKE) -C "$$tmp" package-check

pipx-source-smoke:
	$(PYTHON) -m pip install --upgrade pip pipx
	PYTHON_BIN=$(PYTHON) bash scripts/p1_pipx_source_smoke.sh

release-check:
	$(MAKE) workflow-check
	$(MAKE) pipx-source-smoke
	$(MAKE) demo-sync-check

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
