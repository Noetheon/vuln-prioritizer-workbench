# VPW-062 Asset Context Matching

VPW-062 documents the asset context CSV schema and deterministic matching rules
used to attach local operational context to normalized findings.

## Artifacts

- Schema documentation: `docs/asset-context-csv.md`
- Rule fixture: `data/input_fixtures/example_asset_context_rules.csv`
- Existing exact-match fixture: `data/input_fixtures/example_asset_context.csv`
- Contract references: `docs/contracts.md`, `docs/support_matrix.md`

## Acceptance Coverage

| Requirement | Evidence |
| --- | --- |
| Required columns are documented | `docs/asset-context-csv.md` lists `target_kind`, `target_ref` or `asset_ref`, and `asset_id`. |
| `asset_ref` alias is documented | The schema doc states that `asset_ref` is a backward-compatible alias and that `target_ref` wins when both are present. |
| Match modes are documented | The schema doc covers case-sensitive `exact`, `contains`, `regex`, and compatibility `glob`. |
| Precedence and tie-breaks are documented | The schema doc lists deterministic ordering by precedence, match mode specificity, literal characters, wildcard count, and CSV row. |
| Invalid enum warning behavior is documented | Unknown `criticality`, `exposure`, and `environment` values are documented as field-level warnings; invalid `match_mode`, regex, and precedence values remain validation errors. |
| Operational re-score semantics are documented | The schema doc states that asset context changes operational score and explanation/routing context, not the base priority label. |
| Sample artifact is present | `data/input_fixtures/example_asset_context_rules.csv` includes exact, contains, regex, glob, and `asset_ref` alias examples. |

## Verification

```text
$ python3 -m ruff check backend/src/vuln_prioritizer/commands/input.py backend/src/vuln_prioritizer/inputs/loader.py backend/src/vuln_prioritizer/inputs/_occurrence_support.py backend/tests/test_asset_context_rules.py backend/tests/cli/test_input_validate.py
All checks passed!
```

```text
$ python3 -m pytest -q backend/tests/test_asset_context_rules.py backend/tests/cli/test_input_validate.py --no-cov
14 passed in 0.12s
```

Schema coverage after adding the published `contains_rules` and `regex_rules`
fields:

```text
$ python3 -m pytest -q backend/tests/test_asset_context_rules.py backend/tests/cli/test_input_validate.py backend/tests/test_output_schemas.py --no-cov
45 passed in 1.02s
```

Compatibility coverage for existing exact/glob conflict behavior:

```text
$ python3 -m pytest -q backend/tests/cli/test_analyze.py::test_cli_analyze_reports_asset_and_vex_conflicts_with_deterministic_winners backend/tests/e2e/test_module_entrypoint.py::test_module_entrypoint_p2_context_round_trip --no-cov
2 passed in 2.60s
```

Docs build:

```text
$ make docs-check
Documentation built in 0.67 seconds
```

`mkdocs` still reports the pre-existing informational note that
`architecture/vpw-011-api-skeleton.md` exists outside the nav.

## CLI Validation Excerpt

```text
$ python3 -m vuln_prioritizer.cli input validate --asset-context data/input_fixtures/example_asset_context_rules.csv --format json

asset_context.loaded_rows = 6
asset_context.exact_rules = 3
asset_context.contains_rules = 1
asset_context.regex_rules = 1
asset_context.glob_rules = 1
asset_context.warnings = []
summary.ok = true
summary.asset_context_rules = 6
summary.asset_context_skipped_rows = 0
summary.warning_count = 0
```

## Notes

Asset context remains a local defensive context layer. It does not fetch provider
data, derive CVE-to-asset mappings, or scan infrastructure.
