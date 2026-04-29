# VPW-056 Curated ATT&CK Mapping Loader Evidence

## Scope

VPW-056 adds a reviewed local CVE-to-ATT&CK mapping path for
`data/cve_attack_mappings.yml`.

Implemented scope:

- `local-curated` ATT&CK source for CLI validation, coverage, navigator, and
  analysis option resolution.
- YAML/JSON curated mapping loader with CVE ID, ATT&CK technique ID, confidence
  enum, source, rationale, reviewer, and defensive-note validation.
- Versioned demo mapping file with six defensive mappings.
- Mapping quality report with low-confidence and review-status counts.

## Evidence Artifacts

- Demo mapping file: `data/cve_attack_mappings.yml`
- Mapping quality report: `docs/evidence/vpw-056-mapping-quality-report.json`
- Curated mapping schema: `docs/schemas/attack-curated-mapping.schema.json`
- Methodology: `docs/attack-ttp-methodology.md`

## Mapping Quality Summary

- Mapping count: 6
- Unique CVEs: 6
- Unique techniques: 3
- Confidence distribution: `high=3`, `medium=2`, `low=1`
- Review status distribution: `reviewed=5`, `needs_review=1`
- Low-confidence mappings: 1

The low-confidence entry is intentionally retained to prove validator/report
flagging:

- `CVE-2021-26855` / `T1046`, `review_status=needs_review`

## Safety Review

- Heuristic and LLM-generated sources are rejected by the loader.
- `review_status=reviewed`, `rejected`, or `stale` requires `reviewer` and
  `reviewed_at`.
- `confidence=high` requires `review_status=reviewed`.
- Free-text `rationale`, `comments`, and `defensive_note` remain defensive
  triage context only. The validator enforces required fields, but human review
  remains responsible for prose safety.

## Commands

```bash
python3 -m pytest -q backend/tests/test_providers.py::test_curated_attack_mapping_provider_loads_yaml_fixture backend/tests/test_providers.py::test_curated_attack_mapping_provider_rejects_missing_reviewer_for_reviewed backend/tests/test_providers.py::test_curated_attack_mapping_provider_rejects_numeric_confidence backend/tests/test_providers.py::test_curated_attack_mapping_provider_rejects_invalid_cve_and_attack_ids backend/tests/test_providers.py::test_attack_provider_local_curated_enriches_structured_attack_data --no-cov
python3 -m pytest -q backend/tests/test_output_schemas.py::test_published_schema_documents_are_valid_json_schema backend/tests/test_output_schemas.py::test_attack_curated_mapping_example_matches_schema backend/tests/test_output_schemas.py::test_attack_curated_mapping_demo_yaml_matches_schema backend/tests/test_output_schemas.py::test_attack_curated_mapping_schema_rejects_unreviewable_mappings backend/tests/test_output_schemas.py::test_attack_validation_local_curated_json_matches_published_schema --no-cov
python3 -m pytest -q backend/tests/test_cli_attack.py::test_cli_attack_validate_local_curated_reports_quality backend/tests/test_cli_attack.py::test_cli_attack_validate_local_curated_invalid_file_exits_cleanly backend/tests/test_cli_attack.py::test_cli_attack_coverage_local_curated_works_offline --no-cov
python3 -m pytest -q backend/tests/test_attack_enrichment.py::test_attack_enrichment_service_marks_curated_context_relevance backend/tests/test_analysis_refactor.py::test_analysis_service_resolves_attack_option_modes backend/tests/test_workbench_guardrail_helpers.py::test_workbench_attack_source_guardrails_allow_only_reviewable_sources --no-cov
python3 -m vuln_prioritizer.cli attack validate --attack-source local-curated --attack-mapping-file data/cve_attack_mappings.yml --output docs/evidence/vpw-056-mapping-quality-report.json --format json
make docs-check
make check
```

Targeted test result: 16 passed.
Full gate result: 780 passed, 5 skipped, coverage 90.61%.
