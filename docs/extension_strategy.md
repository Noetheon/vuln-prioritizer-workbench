# Extension Strategy

This project supports new parser and provider contributions through reviewed,
static local extension points. It does not load runtime plugins from package
entry points, user-supplied paths, remote URLs, or scanner output. New formats
and providers are added as normal repository changes with fixtures, tests, docs,
and security review.

The extension policy is intentionally conservative:

- `STATIC_EXTENSION_POLICY = "static-local-only"` for input parsers
- `STATIC_PROVIDER_EXTENSION_POLICY = "static-local-only"` for enrichment providers
- no dynamic code loading, subprocess execution, or remote plugin discovery
- no exploit, proof-of-concept, active probing, credential testing, scanner
  execution, autopatching, or heuristic CVE-to-ATT&CK mapping behavior

## Parser Contract

There are two parser-facing contracts:

- Workbench upload importers implement
  `app.importers.contracts.Importer`.
- Domain input-loader extensions use
  `vuln_prioritizer.inputs.sdk.InputParserDefinition`.

Workbench importers must expose:

- `input_type`: a stable, lowercase Workbench input type
- `parse(payload, *, filename=None)`: deterministic parsing from bytes or text
- `NormalizedOccurrence` output with CVE, component, version, asset reference,
  source, optional fix version, and sanitized raw evidence

Domain parser definitions must declare:

- `name`: stable parser name
- `parser`: callable that accepts a local `Path` and returns `ParsedInput`
- `file_suffixes`: accepted suffixes for review and upload allowlisting
- `media_types`: accepted media types when an HTTP boundary uses the parser
- `fixture_names`: positive and negative fixture names used by tests
- `remote_code_loading = False`

Parser implementations must stay pure. They must not call providers, databases,
FastAPI dependencies, network APIs, subprocesses, or background jobs. Upload
size limits, MIME/suffix checks, project authorization, persistence, provider
enrichment, and HTTP error mapping remain outside the parser layer.

## Provider Contract

Provider extensions use `vuln_prioritizer.providers.sdk.ProviderDefinition` and
a provider object implementing `fetch_many(cve_ids, **kwargs)`.

A provider definition must declare:

- `name`: stable provider source name
- `provider`: object with `fetch_many(...)`
- `source_kind`: reviewed source category
- optional `cache_namespace`, `cache_key_template`, and `cache_ttl_seconds`
- `stale_while_error`: whether stale cache can be used after provider failure
- `offline_capable`: whether fixture or snapshot replay is supported
- `remote_code_loading = False`

Provider implementations must use fixed reviewed HTTPS endpoints or explicit
local fixture/snapshot inputs. They must not accept arbitrary live endpoint
overrides unless a separate security design, allowlist, tests, and threat-model
update are approved. Token values, if required, must be read from explicit
environment variable names at request time and must never be stored in reports,
snapshots, logs, evidence bundles, or database rows.

Provider failures are evidence, not silent success. Providers should populate
diagnostics where possible; the SDK adapter normalizes failures into degraded
`ProviderStatus`, warnings, and data-quality flags.

## Fixture Requirements

Every parser or provider contribution must include small, sanitized fixtures.

Parser fixtures:

- positive fixture with at least one valid CVE occurrence
- negative fixture proving malformed input fails locally
- `data/input_fixtures/normalization_contracts.json` coverage or a focused
  assertion test when the format is intentionally outside the shared manifest
- no secrets, customer data, credentials, absolute local paths, or private URLs
- upload suffix/MIME tests when the HTTP boundary changes

Provider fixtures:

- successful provider response or offline snapshot fixture
- empty/degraded/error fixture where the provider can fail
- cache/status expectations including stale or degraded behavior when relevant
- no live-network-only tests in required CI
- source labels, timestamps, and warnings that make freshness reviewable

Fixture changes are contract changes. Keep them small enough for review and
avoid large scanner exports unless a reduced fixture cannot cover the behavior.

## Contribution Checklist

Before opening a parser or provider PR:

- confirm the change prioritizes known CVEs and does not add scanning behavior
- add or update the static parser/provider definition
- add positive and negative fixtures
- add deterministic tests that run offline
- update the support matrix and format/provider docs
- update API upload allowlists and generated clients if the HTTP contract changes
- update schemas, reports, and evidence-bundle contracts if output changes
- run targeted tests plus `make check`
- run `make docs-check` for documentation changes
- document residual risks and any unsupported fields in the PR

For examples, see `docs/examples/extension_stub.py`. The example is compiled and
exercised by `backend/tests/test_extension_sdk.py`; it is documentation and test
fixture material, not a runtime plugin loader.
