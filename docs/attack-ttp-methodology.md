# ATT&CK/TTP Methodology

This page starts the VPW-055 ATT&CK/TTP methodology for curated local
CVE-to-ATT&CK mappings. It complements the Workbench ATT&CK methodology and
documents the local artifact contract used for reviewable defensive context.

## Scope

Curated mappings are defensive evidence. They may help operators explain
exposure, prioritize review, and check detection coverage. They must not claim
that exploitation happened, and they must not include commands, payloads, or
step-by-step procedure guidance.

The preferred source for CVE-to-ATT&CK mapping remains CTID Mappings Explorer
JSON. Local curated mappings are allowed only when every entry is explicitly
reviewable.

## Required Fields

Every curated mapping object must include:

| Field | Requirement |
| --- | --- |
| `cve_id` | CVE identifier such as `CVE-2021-44228`. `capability_id` may be supplied only as a CTID-compatible alias. |
| `technique_id` | ATT&CK technique or sub-technique ID, matching `T####` or `T####.###`. `attack_object_id` may be supplied only as a CTID-compatible alias. |
| `mapping_type` | One of `exploitation`, `impact`, `post_exploitation`, `mitigation_context`, or `detection_context`. |
| `source` | Human-readable source for the mapping. |
| `confidence` | Enum bucket: `low`, `medium`, or `high`. Numeric confidence values are rejected by the curated artifact validator. |
| `rationale` | Defensive reason for the mapping. |
| `review_status` | One of `unreviewed`, `needs_review`, `reviewed`, `rejected`, or `stale`. |
| `defensive_note` | Required safety note that frames the mapping as defensive context only. |

Optional fields such as `capability_description`, `comments`, and `references`
must remain high-level defensive context. They must not contain exploit payloads,
reproduction steps, credential-testing guidance, or command sequences.

Reviewer rules are enforced by the loader and schema:

- `review_status=reviewed`, `rejected`, or `stale` requires `reviewer` and
  `reviewed_at`.
- `confidence=high` requires `review_status=reviewed`.
- `confidence=low` remains valid but is highlighted in the mapping quality
  report.

## Schema And Example

- Schema: [`docs/schemas/attack-curated-mapping.schema.json`](schemas/attack-curated-mapping.schema.json)
- Example: [`docs/examples/example_attack_curated_mapping.json`](examples/example_attack_curated_mapping.json)

The canonical demo file for the duplicate VPW execution track is
`data/cve_attack_mappings.yml`. The schema accepts JSON and YAML-compatible
object shapes after parsing. YAML files should use the same keys as the JSON
example.

## Validation

Use the published schema for local artifact checks:

```bash
python3 -m pytest -q backend/tests/test_output_schemas.py::test_attack_curated_mapping_example_matches_schema --no-cov
python3 -m vuln_prioritizer.cli attack validate --attack-source local-curated --attack-mapping-file data/cve_attack_mappings.yml --format json
```

The schema and loader reject missing `source`, `rationale`, `confidence`,
reviewer metadata, and malformed ATT&CK technique IDs. Free-text safety still
requires human review; JSON Schema cannot reliably prove that prose contains no
offensive procedure guidance.
