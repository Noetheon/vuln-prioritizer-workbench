# VPW-013 Importer Contract

## Scope

VPW-013 defines the Workbench importer contract for turning an uploaded
input payload into normalized vulnerability occurrences.

Importers are pure parser adapters. They do not own project authorization,
database writes, provider enrichment, analysis runs, or HTTP error mapping.
Those concerns stay outside the importer layer and are handled later by the API
or service boundary.

## Importer Protocol

An importer implements the `Importer` protocol:

- `input_type`: stable Workbench input type string claimed by the importer
- `parse(payload, *, filename=None)`: parses `bytes` or `str` input and returns
  a list of `NormalizedOccurrence`

`parse` must be deterministic for the supplied payload and optional filename.
It must not call FastAPI dependencies, repositories, database sessions,
provider clients, network APIs, background jobs, or application settings.

## NormalizedOccurrence

`NormalizedOccurrence` is the provider-free DTO emitted before persistence.

Fields:

- `cve`: required CVE identifier, normalized to uppercase
- `component`: optional affected component or package name
- `version`: optional affected component version
- `target_ref`: optional source target reference
- `source`: required non-blank occurrence source, defaulting to `import`
- `fix_version`: optional fixed version
- `raw_evidence`: mapping with source-specific evidence, copied to a plain dict

Validation is local to the DTO:

- CVE values must match `CVE-YYYY-NNNN...`
- `source` must not be blank
- `raw_evidence` must be a mapping
- `raw_evidence` keys must be strings

The DTO intentionally contains no CVSS, EPSS, KEV, ATT&CK, provider snapshot, or
database identity fields. Enrichment and persistence attach that context later.

## Registry Lookup

`ImporterRegistry` is an in-memory registry keyed by normalized `input_type`.

Registry behavior:

- registration strips whitespace and lowercases input types
- duplicate input types raise `DuplicateInputTypeError`
- `list_input_types()`, `supported_input_types()`, and `list()` return supported
  input types in stable sorted order
- `get(input_type)` returns the matching importer or raises
  `UnsupportedInputTypeError`
- `parse(input_type, payload, *, filename=None)` resolves the importer and runs
  the selected parse path

`build_importer_registry()` builds the default mapping for the current local
Workbench input types. Passing an explicit iterable builds a scoped registry for
tests or future plugin-free extension points.

## Shared Normalization Fixture Contract

The shared positive parser contract lives in
`data/input_fixtures/normalization_contracts.json`. It is test evidence for
deterministic API importer and domain input-loader normalization; it is not a
runtime API and does not change the upload, database, or OpenAPI contracts.

Each input fixture in the manifest records the raw shape, expected total rows,
expected occurrence count, unique CVE order, skipped non-CVE advisory IDs, and
the normalized occurrence fields shared by the Workbench API importer and the
domain `InputLoader`.

| Input type | Positive fixture | Normalization coverage |
| --- | --- | --- |
| `cve-list` | `parser_matrix/cve-list/positive.txt` | Uppercase normalization and duplicate suppression |
| `generic-occurrence-csv` | `parser_matrix/generic-occurrence-csv/positive.csv` | Component, version, PURL, fix version, severity, and target evidence |
| Scanner, SBOM, GitHub alert, Nessus, and OpenVAS formats | format-specific fixtures under `data/input_fixtures/` | Source metadata, package fields, affected paths, fix versions, raw severity, non-CVE advisory filtering, and CVE order |

`backend/tests/api/import_contracts/test_import_parser_contracts.py` loads every manifest
fixture through `build_importer_registry()` and compares normalized occurrences
to the same projection asserted by the domain
`backend/tests/test_input_loader_contracts.py` tests.

Workbench parse-error fixtures live under `data/input_fixtures/parser_matrix/`.
They cover fail-closed API upload behavior, not positive normalization
snapshots. `cve-list` and `generic-occurrence-csv` intentionally fail closed on
mixed invalid uploaded rows: the Workbench importer raises
`ImporterParseError` with sanitized row context instead of silently skipping
invalid CVEs.

Maintenance rules:

- keep fixtures small, sanitized, and free of local paths, secrets, credentials,
  and customer data
- do not call scanners, provider APIs, or network services from parser fixture
  tests
- treat `normalization_contracts.json` changes as parser contract changes that
  need review
- keep parse-error and persistence behavior in API/service tests instead of
  mixing it into pure parser fixture tests
- when adding a new Workbench import type, add the positive fixture to
  `normalization_contracts.json`, add a negative parser fixture when the API
  failure semantics need coverage, and cover upload suffix/MIME handling
  separately if the HTTP boundary changes

## Domain Exceptions

Importer-layer failures use domain exceptions, not FastAPI exceptions:

- `ImporterError`: base importer contract failure
- `ImporterParseError`: payload could not be parsed by the selected importer
- `ImporterValidationError`: normalized output failed importer validation
- `UnsupportedInputTypeError`: no importer is registered for an input type
- `DuplicateInputTypeError`: more than one importer claims an input type

The API/service boundary maps these domain exceptions to HTTP responses, run
error state, and user-facing messages. Importers should not raise
`HTTPException` or know about response status codes.

For Workbench import uploads, parse and validation failures are stored on the
`AnalysisRun` as structured `parse_errors` and returned from
`GET /api/v1/runs/{run_id}/summary`. Each parse error includes `input_type`,
`filename`, `message`, `error_type`, and optional `line`, `field`, and `value`
when the API can derive those details from the importer exception.

## Non-Goals

This contract does not introduce scanner execution, live provider lookups,
remote plugin discovery, database persistence, report generation, or ATT&CK
inference. It only defines the local normalization boundary for uploaded input
payloads.
