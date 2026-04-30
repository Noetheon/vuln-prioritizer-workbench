# VPW-078 CTID Mappings Provider Evidence

## Scope

VPW-078 implements the duplicate roadmap CTID Mappings Explorer provider MVP.
It keeps CTID JSON as the canonical Workbench CVE-to-ATT&CK source and does not
add generated or heuristic mappings.

Implemented scope:

- CTID dataset fixture import from
  `data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json`.
- CTID mapping normalization to `source=ctid-mappings-explorer`,
  `confidence=high`, and `review_status=reviewed`.
- Mapping quality report for `attack validate --attack-source ctid-json`.
- Visible duplicate-context conflict reporting for CVE/technique pairs with
  multiple CTID mapping contexts.
- Explicit local-vs-CTID comparison via `--comparison-mapping-file`: CTID and
  local curated mappings are selected sources, not silently merged.

## Evidence Artifacts

- CTID fixture:
  `data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json`
- Technique metadata fixture:
  `data/attack/attack_techniques_enterprise_16.1_subset.json`
- Mapping quality report:
  `docs/evidence/vpw-078-ctid-mapping-quality-report.json`
- Methodology:
  `docs/attack-ttp-methodology.md`

## Mapping Quality Summary

The generated quality report records:

- Mapping count: 27
- Unique CVEs: 3
- Unique techniques: 22
- Source distribution: `ctid-mappings-explorer=27`
- Confidence distribution: `high=27`
- Review status distribution: `reviewed=27`
- Mapping type distribution:
  `exploitation_technique=4`, `primary_impact=5`, `secondary_impact=18`
- Visible duplicate-context conflicts: 2
- Local-vs-CTID conflicts when compared to `data/cve_attack_mappings.yml`: 1
- Low-confidence mappings: 0

The two visible conflicts are both for `CVE-2020-1472` and document CTID rows
where the same technique appears with more than one mapping context:

- `T1087.002`: `primary_impact` and `secondary_impact`
- `T1133`: `exploitation_technique` and `secondary_impact`

## Commands

```bash
python3 -m ruff check backend/src/vuln_prioritizer/providers/ctid_mappings.py backend/src/vuln_prioritizer/cli_support/attack_support.py backend/tests/test_providers.py backend/tests/test_cli_attack.py
python3 -m pytest -q backend/tests/test_providers.py::test_ctid_provider_loads_official_subset_fixture backend/tests/test_providers.py::test_attack_provider_ctid_json_enriches_structured_attack_data backend/tests/test_cli_attack.py::test_cli_attack_validate_json_reports_stix_and_hash_provenance backend/tests/test_cli_attack.py::test_cli_attack_validate_ctid_json_reports_quality_for_fixture backend/tests/test_cli_attack.py::test_cli_attack_validate_ctid_json_compares_local_curated_mapping --no-cov
python3 -m vuln_prioritizer.cli attack validate --attack-source ctid-json --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json --output docs/evidence/vpw-078-ctid-mapping-quality-report.json --format json
python3 -m vuln_prioritizer.cli attack validate --attack-source ctid-json --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json --comparison-mapping-file data/cve_attack_mappings.yml --format json
python3 -m vuln_prioritizer.cli attack coverage --input data/sample_cves_mixed.txt --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json --output build/vpw-078-attack-coverage.json --format json
```

Targeted result: 5 focused tests passed; the broader CTID/CLI/schema slice
passed with 22 tests. `make docs-check` passed.
