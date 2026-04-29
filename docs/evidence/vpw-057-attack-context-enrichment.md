# VPW-057 ATT&CK Finding Context Evidence

## Scope

VPW-057 adds explicit finding-level ATT&CK context for analysis and Workbench
detail payloads.

Implemented scope:

- `PrioritizedFinding.attack_context` with mapped/unmapped state, source
  metadata, tactic/technique arrays, mappings, and confidence.
- Curated mapping confidence and review metadata preserved on `AttackMapping`.
- Workbench finding detail response includes the latest stored
  `attack_context`.
- Low-confidence ATT&CK context appears as review-only explanation note and does
  not change hard priority label, rank, or priority drivers.

## Evidence Artifacts

- Example mapped/unmapped context JSON:
  `docs/evidence/vpw-057-finding-attack-context.json`
- Published schema updates:
  `docs/schemas/analysis-report.schema.json`,
  `docs/schemas/explain-report.schema.json`,
  `docs/schemas/snapshot-report.schema.json`
- Contract documentation: `docs/contracts.md`

## Expected Context Semantics

- Mapped finding: `mapped=true`, ATT&CK technique/tactic rows present, and
  `confidence` is populated when the source supplies curated confidence.
- Unmapped finding: `mapped=false`, `source=none`, `confidence=null`, and empty
  `techniques`, `tactics`, and `mappings` arrays.
- Low-confidence finding: explanation includes `attack.low_confidence`; base
  priority remains driven by CVSS, EPSS, and KEV only.

## Commands

```bash
python3 -m pytest -q backend/tests/test_providers.py::test_curated_attack_mapping_provider_loads_yaml_fixture backend/tests/test_scoring.py::test_attack_context_does_not_change_priority backend/tests/test_workbench_guardrail_helpers.py::test_workbench_attack_review_confidence_and_payload_helpers backend/tests/cli/test_analyze.py::test_cli_analyze_emits_attack_context_with_confidence_and_empty_state backend/tests/cli/test_explain.py::test_cli_explain_end_to_end_with_mocked_providers backend/tests/api/test_workbench_api.py::test_workbench_attack_import_exposes_ttp_context_and_navigator backend/tests/db/test_workbench_db.py::test_repository_round_trip_persists_workbench_finding backend/tests/test_output_schemas.py::test_vpw_057_attack_context_schema_fields_remain_optional --no-cov
python3 -m pytest -q backend/tests/test_output_schemas.py::test_published_schema_documents_are_valid_json_schema backend/tests/test_output_schemas.py::test_analysis_json_matches_published_schema backend/tests/test_output_schemas.py::test_explain_json_matches_published_schema backend/tests/test_output_schemas.py::test_attack_validation_local_curated_json_matches_published_schema backend/tests/test_output_schemas.py::test_vpw_057_attack_context_schema_fields_remain_optional --no-cov
make docs-check
make check
```

Targeted VPW-057 test result: 8 passed.
Published-schema validation result: 5 passed.
Documentation build result: passed; existing informational mkdocs note remains
for `architecture/vpw-011-api-skeleton.md`.
Full gate result: 782 passed, 5 skipped, coverage 90.59%.
