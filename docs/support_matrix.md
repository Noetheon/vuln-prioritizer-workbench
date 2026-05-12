# Support Matrix

## Command matrix

The GitHub composite Action is checked against the CLI through
`backend/tests/test_github_action_contract.py`. That test writes the local
machine-readable parity artifact `build/cli-action-parity.json` and fails if an
advertised Action mode no longer maps to a CLI command.

| Command | Primary input | Supported file outputs | Current machine contract | Notes |
| --- | --- | --- | --- | --- |
| `analyze` | repeatable `--input PATH` | `markdown`, `json`, `sarif`, `html` sidecar via `--html-output` | JSON schema + SARIF 2.1.0 | `table` is terminal-only. Direct HTML is additive and does not replace the JSON contract. Optional local defensive context, waiver lifecycle gates, and provider freshness gates are available for CI. |
| `compare` | repeatable `--input PATH` | `markdown`, `json` | JSON schema | Comparison is `CVSS-only` vs enriched. Provider freshness gates are additive and use the same semantics as `analyze`. |
| `explain` | `--cve CVE-...` | `markdown`, `json` | JSON schema | Single-CVE detailed view. |
| `doctor` | optional local files and runtime config | `json` | JSON schema | Local environment, cache, file, waiver-health, and optional live-source diagnostics. |
| `snapshot create` | repeatable `--input PATH` | `markdown`, `json` | JSON schema | Reusable point-in-time artifact over the same prioritization pipeline as `analyze`, including local defensive context and provider freshness metadata when requested. |
| `snapshot diff` | two snapshot JSON files | `markdown`, `json` | JSON schema | Categorizes `added`, `removed`, priority, and context changes per CVE. |
| `state init` | `--db PATH` | `json` | JSON schema | Initializes the optional local SQLite backing store used only for persisted snapshot history. |
| `state import-snapshot` | snapshot JSON file | `json` | JSON schema | Imports a saved `snapshot create --format json` artifact into the optional local SQLite state store. |
| `state history` | local SQLite DB + `--cve` | `json` | JSON schema | Returns persisted per-CVE history across imported snapshots. |
| `state waivers` | local SQLite DB | `json` | JSON schema | Shows persisted waiver lifecycle debt from the latest snapshot or full imported history. |
| `state top-services` | local SQLite DB | `json` | JSON schema | Shows repeated service pressure across imported snapshots without rerunning enrichment. |
| `state trends` | local SQLite DB | `json` | JSON schema | Shows per-snapshot priority, KEV, ATT&CK, and waiver trends from imported snapshots. |
| `state service-history` | local SQLite DB + `--service NAME` | `json` | JSON schema | Shows per-service history across imported snapshots without rerunning enrichment. |
| `input validate` | repeatable `--input PATH`, optional asset/VEX files | `json` | JSON schema | Performs local parser, asset context, and VEX validation without provider lookups. |
| `input inspect` / `input normalize` | repeatable `--input PATH`, optional asset/VEX files | `json` | JSON shape documented in contracts | Emits normalized occurrences and source summaries without provider lookups. `normalize` is an alias over the same contract. |
| `rollup` | analysis JSON or snapshot JSON | `markdown`, `json` | JSON schema | Aggregates findings by `asset_id` or `asset_business_service`, keeps waiver lifecycle debt visible, and ranks buckets for remediation planning without rerunning enrichment. |
| `attack validate` | ATT&CK local files | `markdown`, `json` | JSON schema | Validates local mapping and metadata artifacts; `ctid-json` is the preferred workflow. |
| `attack coverage` | `--input PATH` | `markdown`, `json` | JSON schema | Uses the same input loader for CVE extraction. |
| `attack navigator-layer` | `--input PATH` | Navigator layer JSON | Navigator JSON, no local schema here | Exports a frequency-based ATT&CK Navigator layer. The Workbench also exposes `attack-navigator` and `sarif` as run report artifacts. |
| `data status` | none | `json` | JSON schema | Cache namespace inspection plus optional local ATT&CK metadata validation. |
| `data update` | optional repeatable `--input PATH` / `--cve` | `json` | JSON schema | Cache refresh for `nvd`, `epss`, and `kev`; `table` remains the default terminal view. |
| `data verify` | optional repeatable `--input PATH` / `--cve` | `json` | JSON schema | Cache coverage, checksum, and pinned local file verification; `table` remains the default terminal view. |
| `data export-provider-snapshot` | repeatable `--input PATH` and/or `--cve` | `json` | JSON schema | Exports replayable provider data for `nvd`, `epss`, and `kev` so later analysis can run in fallback or locked snapshot mode. |
| `report workbench` | analysis JSON | `json`, `markdown`, `html`, `csv`, `sarif` | Saved analysis JSON contract + SARIF 2.1.0 | No live enrichment during rendering. SARIF results use CVE-addressable rules and references. |
| `report html` | analysis JSON | `html` | Consumes analysis JSON contract | No live enrichment during rendering. |
| `report evidence-bundle` | analysis JSON | `zip` | Manifest schema inside bundle | Packages saved analysis JSON, regenerated HTML, Markdown summary, optional source input copy, and optional ATT&CK Navigator layer when mappings exist. |
| `report verify-evidence-bundle` | evidence ZIP | `json` | JSON schema | Verifies ZIP members against the embedded manifest and reports missing, modified, unexpected, or malformed bundle content. |

## Input-format matrix

Workbench imports require an explicit `input_type`; CLI `auto` remains a CLI
convenience and is not a persisted Workbench upload type. The Workbench importer
registry otherwise matches the concrete `InputFormat` values.

| `--input-format` | Auto-detect | `analyze` / `compare` | Workbench import | `attack coverage` / `navigator-layer` | Normalized provenance currently preserved | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `cve-list` | `.txt`, `.csv` | yes | yes | yes | `cve_id`, optional `asset_ref`, `component`, `version`, source line/row | Plain TXT and minimal CSV CVE lists; see [CVE List Import](cve-list-import.md). |
| `generic-occurrence-csv` | CSV with `cve`/`cve_id` plus optional component, version, PURL, fix, target, asset, owner, service, severity columns | yes | yes | yes | component, version, purl, fix versions, target, asset context, owner, service | Additive manual-occurrence format for normalized backlog and spreadsheet exports; see [Generic Occurrence CSV Import](generic-occurrence-csv-import.md). |
| `trivy-json` | JSON with `Results` | yes | yes | yes | component, version, purl, package type, path, fix versions, target image, source ID | Default target kind is `image`; see [Trivy JSON Import](trivy-json-import.md). |
| `grype-json` | JSON with `matches` | yes | yes | yes | component, version, purl, package type, path, fix versions, target image, source ID | Keeps the first artifact location as current path evidence; see [Grype JSON Import](grype-json-import.md). |
| `cyclonedx-json` | JSON with `bomFormat=CycloneDX` and vulnerabilities | yes | yes | yes | component refs, purl, versions, dependency context when present | Used for SBOM+vuln exports, not plain BOMs without vulnerabilities. |
| `spdx-json` | JSON with `spdxVersion` | yes | yes | yes | package names, versions, file names when available | Current support is JSON only. |
| `dependency-check-json` | JSON with `scanInfo` and `dependencies` | yes | yes | yes | dependency path, package/file names, severity, fix/version hints where present | Current support is JSON only. |
| `github-alerts-json` | JSON array or alert-like object | yes | yes | yes | advisory source, package context when present | Contract assumes a pinned JSON export shape, not arbitrary API responses. |
| `nessus-xml` | `.nessus` | yes | yes | yes | host target, plugin name, service/port label, severity, source record id | Pinned Nessus XML export shape. Only resolvable CVEs are normalized. |
| `openvas-xml` | pinned OpenVAS-style `.xml` | yes | yes | yes | host target, NVT name, severity, source record id | Prefer explicit `--input-format openvas-xml` in CI. Only resolvable CVEs are normalized. |

Maintainer-facing parser fixture regression coverage is documented in
[VPW-013 Importer Contract](architecture/vpw-013-importer-contract.md).
Contributor-facing parser and provider extension rules are documented in the
[Extension Strategy](extension_strategy.md); extensions are reviewed static
repository changes, not runtime plugin discovery.

## Feature overlay matrix

| Feature | `analyze` | `compare` | `explain` | Notes |
| --- | --- | --- | --- | --- |
| ATT&CK enrichment | yes | yes | yes | Sources: `none`, `local-csv`, `local-curated`, `ctid-json`. Prefer `ctid-json`; `local-curated` is for reviewed YAML/JSON CVE-to-ATT&CK mappings; `local-csv` remains legacy compatibility only. Technique metadata can use the simplified local JSON or a pinned ATT&CK STIX bundle. No remote ATT&CK dependency. |
| Defensive context file | yes | yes | yes | `--defensive-context-file` reads a local/offline JSON overlay for OSV, GHSA, Vulnrichment, or SSVC evidence you already have. It is contextual evidence only; it does not fetch advisory data and does not change base priority scoring from CVSS, EPSS, and KEV. |
| Asset context CSV | yes | yes | yes | `target_kind` stays exact; `target_ref` or `asset_ref` supports deterministic `exact`, `contains`, `regex`, and compatibility `glob` rules with optional `rule_id`, `match_mode`, `precedence`, and aggregated conflict reporting; see [Asset Context CSV](asset-context-csv.md). |
| VEX files | yes | yes | yes | Supports OpenVEX JSON and CycloneDX VEX JSON with deterministic ranked matching, occurrence-level match provenance, aggregated conflict reporting, and visible `under_investigation` status. CycloneDX VEX applies only from `vulnerabilities[].affects[].ref` entries that resolve to component `bom-ref` values or direct PURLs. |
| Policy profiles | yes | yes | yes | Built-ins: `default`, `enterprise`, `conservative`. |
| Custom policy file | yes | yes | yes | YAML-defined profiles, selected by `--policy-profile`. |
| Waiver file | yes | yes | yes | YAML risk-acceptance rules mark findings as waived without deleting the underlying prioritization evidence. Optional `review_on` plus automatic near-expiry handling keep stale waivers visible. |
| Runtime config discovery | yes | yes | yes | Also applies to `doctor`, `snapshot create`, `rollup`, `attack.*`, and `data.*` where relevant defaults exist. |
| `--show-suppressed` | yes | yes | yes | Reveals findings fully suppressed by VEX. |
| `--hide-waived` | yes | yes | no | Keeps waiver governance visible in metadata while removing waived findings from the default visible list. |
| `--fail-on` | yes | no | no | Returns exit code `1` when the threshold is met. |

## Explain-specific context notes

`explain` does not load a scanner or SBOM file. It builds a single inline occurrence from `--cve` and optional manual targeting fields.

To make asset context or VEX matching meaningful with `explain`, provide:

- `--target-kind`
- `--target-ref`
- optional `--asset-context`
- optional `--vex-file`

Without a matching target, the explain flow still works, but asset-context and VEX applicability may remain empty.

## Output notes

- Run `doctor` first when installation, runtime config, cache health, ATT&CK inputs, or live source reachability is unclear.
- For automation, key off `doctor` `check_id` and `status`, not the human-readable `detail` text.
- Prefer JSON for automation.
- Prefer `--input-format` over `auto` in CI if reproducibility matters.
- Prefer `--html-output` when one analyze run needs both machine-readable JSON and a human-facing HTML artifact.
- Prefer Workbench report generation when local review needs a compact Markdown
  executive summary.
- Prefer `state import-snapshot` plus `state history|waivers|top-services|trends|service-history` when you need repeated local review over saved snapshots rather than another live enrichment run.
- Prefer `report evidence-bundle` when a review board or release gate needs a reproducible offline artifact set from a saved analysis run.
- Prefer `report verify-evidence-bundle` before shipping or archiving an evidence ZIP outside the repository or CI workspace.
- `report html` expects an analysis JSON export, not compare JSON or explain JSON.
- `sarif` is part of the documented contract for `analyze`, `report workbench`,
  and Workbench run reports. CLI `report workbench --format csv` and Workbench
  CSV reports are locked to the same header contract by parity tests; both SARIF
  surfaces use the same local validator before upload or download evidence.
- `data status`, `data update`, `data verify`, and `data export-provider-snapshot` publish JSON contracts; their Rich table layout remains human-facing where applicable.
- `data export-provider-snapshot`, Workbench provider update jobs, snapshot replay,
  and `/api/v1/providers/status` share the `provider-snapshot.v1.json`
  metadata vocabulary. Workbench status redacts local cache/snapshot paths in
  production-safe mode while retaining selected sources, cache-only mode,
  requested CVE counts, hashes, and source metadata.
- The optional SQLite state store is separate from the existing file cache and does not change `analyze`, `snapshot`, or `report` output semantics.
- Workbench imports now accept the same input-format matrix as the CLI for single-upload and multi-upload import flows.
- Workbench artifact retention, cleanup, detection-control history/attachments, config export/defaults, and ATT&CK review queue APIs are additive local Workbench surfaces.
- Workbench supports implemented GitHub issue preview/export with dry-run defaults,
  report-scope previews, admin-scope real issue creation, persisted duplicate keys,
  and explicit token environment variables. Jira and
  ServiceNow preview/export flows are not implemented in the active Workbench
  codebase and should be treated as future integrations until a separate
  implementation, tests, and threat-model update ship.
- Parser/provider SDK definitions are static local contracts and do not discover entry points or load remote code.
- `vuln-prioritizer.yml` is the documented runtime-config filename; `--config` and `--no-config` are the stable CLI overrides.
