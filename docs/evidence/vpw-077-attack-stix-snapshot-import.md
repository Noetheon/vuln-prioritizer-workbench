# VPW-077 ATT&CK STIX Snapshot Import Evidence

VPW-077 implements a reproducible, local-only ATT&CK STIX 2.1 snapshot import
for the template Workbench backend.

## Delivered Scope

- Extended the pinned STIX parser to read `x-mitre-tactic`, `attack-pattern`,
  `x-mitre-collection`, `course-of-action`, and `mitigates` relationship
  objects while keeping the existing technique-metadata loader compatible.
- Preserved official MITRE collection release metadata from `x_mitre_version`
  and imported all MITRE `course-of-action` external IDs, including deprecated
  legacy `T*` mitigation IDs.
- Added versioned SQLModel catalog tables:
  `attack_stix_snapshot`, `attack_stix_tactic`, `attack_stix_technique`,
  `attack_stix_mitigation`, and `attack_stix_technique_mitigation`.
- Added Alembic migration `20260430_0007_attack_stix_snapshot_catalog`.
- Added `import_attack_stix_snapshot()` for idempotent fixture imports keyed by
  bundle SHA256.
- Added `validate_attack_technique_ids()` to validate mappings against the
  imported technique catalog and surface missing/revoked/deprecated IDs.
- Persisted ATT&CK version, domain, STIX spec version, bundle SHA256, object
  counts, row counts, source path, and warnings into `ProviderSnapshot`
  `source_hashes_json` and `source_metadata_json`.
- Exposed `attack_stix` as an extra provider-status source only when a snapshot
  includes it.
- Extended the checked-in STIX fixture with collection metadata, tactics, two
  mitigations, one `mitigates` relationship, and revoked/deprecated examples.

## Fixture Coverage

Fixture: `data/attack/attack_stix_enterprise_16.1_subset.json`

Expected catalog rows:

- Tactics: `TA0001`, `TA0002`
- Techniques: `T1190`, `T1059`, `T9999`
- Mitigations: `M1051`, `T9998`
- Relationships: `M1051 mitigates T1190`
- Revoked/deprecated examples: `T9999`, `T9998`

The fixture is committed and loaded from disk. CI does not download live TAXII
or ATT&CK content.

## Provider Status Evidence

`GET /api/v1/providers/status` exposes the imported snapshot through the normal
provider status response:

```json
{
  "snapshot": {
    "selected_sources": ["attack_stix"],
    "source_hashes": {"attack_stix": "<bundle-sha256>"},
    "source_metadata": {
      "attack_version": "16.1",
      "domain": "enterprise",
      "stix_spec_version": "2.1",
      "technique_count": 3,
      "mitigation_count": 2
    },
    "mode": "attack-stix"
  },
  "sources": [
    {
      "name": "attack_stix",
      "selected": true,
      "available": true,
      "value": "16.1"
    }
  ]
}
```

## Validation Commands

```text
python3 -m pytest -q backend/tests/test_providers.py::test_attack_metadata_provider_loads_stix_bundle_fixture backend/tests/test_providers.py::test_attack_stix_provider_loads_versioned_snapshot_catalog backend/tests/test_cli_attack.py::test_cli_attack_validate_json_reports_stix_and_hash_provenance --no-cov
...                                                                      [100%]
3 passed
```

```text
python3 -m pytest -q backend/tests/api/test_template_attack_stix_snapshot_import.py backend/tests/api/test_template_attack_models.py backend/tests/api/test_template_provider_status_api.py --no-cov
..........                                                               [100%]
10 passed
```

```text
git diff --check
passed
```

```text
make docs-check
passed
note: docs/architecture/vpw-011-api-skeleton.md is still outside mkdocs nav
```

```text
make check
843 passed, 7 skipped
coverage: 90.70%
```

## Residual Risk

The import is local-only and fixture-backed. Live ATT&CK/TAXII download,
scheduled refresh, UI management pages, and detection-coverage expansion remain
future VPW-078/VPW-079 style work.
