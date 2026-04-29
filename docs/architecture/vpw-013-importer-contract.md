# VPW-013 Importer Contract

## Scope

VPW-013 defines the template-backend importer contract for turning an uploaded
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
- `asset_ref`: optional source asset reference
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

## Parser Fixture Test Matrix

VPW-021 adds a maintainer-facing regression matrix for the MVP Workbench import
formats. The matrix is test evidence for deterministic parser/importer behavior;
it is not a runtime API and does not change the upload, database, or OpenAPI
contracts.

Fixtures live under `data/input_fixtures/parser_matrix/`. Each MVP format owns a
positive fixture, a negative fixture, and a shared normalized occurrence
snapshot in `expected_normalized_occurrences.json`.

| Input type | Positive fixture | Negative fixture | Snapshot coverage |
| --- | --- | --- | --- |
| `cve-list` | `cve-list/positive.txt` | `cve-list/negative.txt` | Uppercase normalization, duplicate suppression, source line evidence |
| `generic-occurrence-csv` | `generic-occurrence-csv/positive.csv` | `generic-occurrence-csv/negative.csv` | Asset, component, fix version, severity, owner, service, and target evidence |
| `trivy-json` | `trivy-json/positive.json` | `trivy-json/negative.json` | OS and library occurrences, GHSA-to-CVE alias handling, source metadata |
| `grype-json` | `grype-json/positive.json` | `grype-json/negative.json` | Match normalization, related CVE handling, package and target evidence |

`backend/tests/api/test_template_parser_fixture_matrix.py` loads these fixtures
through `build_importer_registry()`, compares normalized occurrences to the
checked-in JSON snapshot, and verifies that each negative fixture fails offline
with `ImporterParseError`.

Maintenance rules:

- keep fixtures small, sanitized, and free of local paths, secrets, credentials,
  and customer data
- do not call scanners, provider APIs, or network services from parser fixture
  tests
- treat snapshot changes as parser contract changes that need review
- keep parse-error and persistence behavior in API/service tests instead of
  mixing it into pure parser fixture tests
- when adding a new Workbench import type, add positive and negative parser
  fixtures, extend the snapshot, update this matrix, and cover upload
  suffix/MIME handling separately if the HTTP boundary changes

The broader CLI/input-loader fixture manifest remains
`data/input_fixtures/normalization_contracts.json`; VPW-021 is the Workbench
MVP importer matrix for `cve-list`, `generic-occurrence-csv`, `trivy-json`, and
`grype-json`.

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

For template import uploads, parse and validation failures are stored on the
`AnalysisRun` as structured `parse_errors` and returned from
`GET /api/v1/runs/{run_id}/summary`. Each parse error includes `input_type`,
`filename`, `message`, `error_type`, and optional `line`, `field`, and `value`
when the API can derive those details from the importer exception.

## Non-Goals

This contract does not introduce scanner execution, live provider lookups,
remote plugin discovery, database persistence, report generation, or ATT&CK
inference. It only defines the local normalization boundary for uploaded input
payloads.
