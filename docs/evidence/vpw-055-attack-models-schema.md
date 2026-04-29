# VPW-055 ATT&CK Models And Schema

VPW-055 defines the defensive ATT&CK Lite data contract for the duplicate VPW
execution cycle.

## Implemented Scope

- Added template backend SQLModel table/DTO models for `AttackTactic`,
  `AttackTechnique`, `CveAttackMapping`, and `FindingAttackContext`.
- Added Alembic migration `20260429_0005_attack_lite_models.py`.
- Extended legacy Pydantic models with `AttackTactic`, `CveAttackMapping`, and
  `FindingAttackContext` validators while keeping existing `AttackData`,
  `AttackMapping`, and `AttackTechnique` compatibility.
- Published `docs/schemas/attack-curated-mapping.schema.json` for reviewed
  JSON or YAML-compatible curated mapping artifacts.
- Added `docs/examples/example_attack_curated_mapping.json`.
- Started `docs/attack-ttp-methodology.md` with required fields, safety notes,
  and update guidance.

## Safety Contract

Curated mappings require source, confidence, rationale, review status, and a
defensive note. Technique IDs must match `T####` or `T####.###`.

Mapping text is defensive triage and detection context only. It must not include
exploit payloads, commands, credential testing guidance, or step-by-step
procedure content.

## Validation

Run:

```bash
python3 -m pytest -q backend/tests/api/test_template_attack_models.py backend/tests/test_model_facade.py::test_vpw055_attack_mapping_models_validate_required_review_fields backend/tests/test_output_schemas.py::test_attack_curated_mapping_example_matches_schema backend/tests/test_output_schemas.py::test_attack_curated_mapping_schema_rejects_unreviewable_mappings --no-cov
python3 -m pytest -q backend/tests/test_output_schemas.py::test_published_schema_documents_are_valid_json_schema backend/tests/test_output_schemas.py::test_contracts_schema_list_matches_schema_directory --no-cov
python3 -m mkdocs build --clean
```

Residual risk: JSON Schema validates required fields and identifier shape, but
human review remains required for free-text safety.
