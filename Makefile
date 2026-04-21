PYTHON ?= python3

ATTACK_MAPPING_FILE := data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json
ATTACK_METADATA_FILE := data/attack/attack_techniques_enterprise_16.1_subset.json

.PHONY: install test lint format typecheck check benchmark-check docs-check docs-serve workflow-check package package-check release-check demo-report demo-compare demo-explain demo-attack-report demo-attack-compare demo-attack-explain demo-attack-coverage demo-attack-navigator demo-pr-comment demo-results-sarif demo-html-report precommit-install

install:
	$(PYTHON) -m pip install -e .[dev]

test:
	pytest

lint:
	$(PYTHON) -m ruff check .

format:
	$(PYTHON) -m ruff format .

typecheck:
	$(PYTHON) -m mypy src

check:
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m ruff check .
	$(PYTHON) -m mypy src
	pytest

benchmark-check:
	$(PYTHON) -m pytest -q tests/test_benchmark_regressions.py tests/test_snapshot_diff_regressions.py

docs-check:
	$(PYTHON) -m mkdocs build --clean

docs-serve:
	$(PYTHON) -m mkdocs serve

workflow-check:
	$(MAKE) check
	$(MAKE) docs-check
	$(PYTHON) -m pre_commit run --all-files
	$(MAKE) package-check

package:
	rm -rf dist
	$(PYTHON) -m build

package-check: package
	$(PYTHON) -m twine check dist/*

release-check:
	$(MAKE) check
	$(MAKE) demo-pr-comment
	$(MAKE) demo-results-sarif
	$(MAKE) demo-html-report
	$(MAKE) demo-report
	$(MAKE) demo-compare
	$(MAKE) demo-explain
	$(MAKE) demo-attack-report
	$(MAKE) demo-attack-compare
	$(MAKE) demo-attack-explain
	$(MAKE) demo-attack-coverage
	$(MAKE) demo-attack-navigator
	$(MAKE) docs-check
	$(PYTHON) -m pre_commit run --all-files
	$(MAKE) package-check

demo-report:
	PYTHONPATH=src $(PYTHON) -m vuln_prioritizer.cli analyze --input data/sample_cves.txt --output docs/example_report.md --format markdown

demo-compare:
	PYTHONPATH=src $(PYTHON) -m vuln_prioritizer.cli compare --input data/sample_cves.txt --output docs/example_compare.md --format markdown

demo-explain:
	PYTHONPATH=src $(PYTHON) -m vuln_prioritizer.cli explain --cve CVE-2021-44228 --output docs/example_explain.json --format json --offline-attack-file data/optional_attack_to_cve.csv

demo-attack-report:
	PYTHONPATH=src $(PYTHON) -m vuln_prioritizer.cli analyze --input data/sample_cves_mixed.txt --output docs/example_attack_report.md --format markdown --attack-source ctid-json --attack-mapping-file $(ATTACK_MAPPING_FILE) --attack-technique-metadata-file $(ATTACK_METADATA_FILE)

demo-attack-compare:
	PYTHONPATH=src $(PYTHON) -m vuln_prioritizer.cli compare --input data/sample_cves_mixed.txt --output docs/example_attack_compare.md --format markdown --attack-source ctid-json --attack-mapping-file $(ATTACK_MAPPING_FILE) --attack-technique-metadata-file $(ATTACK_METADATA_FILE)

demo-attack-explain:
	PYTHONPATH=src $(PYTHON) -m vuln_prioritizer.cli explain --cve CVE-2023-34362 --output docs/example_attack_explain.json --format json --attack-source ctid-json --attack-mapping-file $(ATTACK_MAPPING_FILE) --attack-technique-metadata-file $(ATTACK_METADATA_FILE)

demo-attack-coverage:
	PYTHONPATH=src $(PYTHON) -m vuln_prioritizer.cli attack coverage --input data/sample_cves_mixed.txt --output docs/example_attack_coverage.md --format markdown --attack-mapping-file $(ATTACK_MAPPING_FILE) --attack-technique-metadata-file $(ATTACK_METADATA_FILE)

demo-attack-navigator:
	PYTHONPATH=src $(PYTHON) -m vuln_prioritizer.cli attack navigator-layer --input data/sample_cves_attack.txt --output docs/example_attack_navigator_layer.json --attack-mapping-file $(ATTACK_MAPPING_FILE) --attack-technique-metadata-file $(ATTACK_METADATA_FILE)

demo-pr-comment:
	PYTHONPATH=src $(PYTHON) -m vuln_prioritizer.cli analyze --input data/input_fixtures/trivy_report.json --input-format trivy-json --asset-context data/input_fixtures/example_asset_context.csv --vex-file data/input_fixtures/openvex_statements.json --policy-profile enterprise --output docs/examples/example_pr_comment.md --format markdown

demo-results-sarif:
	PYTHONPATH=src $(PYTHON) -m vuln_prioritizer.cli analyze --input data/input_fixtures/trivy_report.json --input-format trivy-json --asset-context data/input_fixtures/example_asset_context.csv --vex-file data/input_fixtures/openvex_statements.json --policy-profile enterprise --output docs/examples/example_results.sarif --format sarif

demo-html-report:
	mkdir -p build
	PYTHONPATH=src $(PYTHON) -m vuln_prioritizer.cli analyze --input data/input_fixtures/trivy_report.json --input-format trivy-json --asset-context data/input_fixtures/example_asset_context.csv --vex-file data/input_fixtures/openvex_statements.json --policy-profile enterprise --output build/example_report_analysis.json --format json
	PYTHONPATH=src $(PYTHON) -m vuln_prioritizer.cli report html --input build/example_report_analysis.json --output docs/examples/example_report.html

precommit-install:
	pre-commit install
