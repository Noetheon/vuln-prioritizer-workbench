# Support Matrix

## Command matrix

| Command | Primary input | Supported file outputs | Current machine contract | Notes |
| --- | --- | --- | --- | --- |
| `analyze` | repeatable `--input PATH` | `markdown`, `json`, `sarif`, `html` sidecar via `--html-output` | JSON schema + SARIF 2.1.0 | `table` is terminal-only. Direct HTML is additive and does not replace the JSON contract. Optional waiver lifecycle gates exist via `--fail-on-expired-waivers` and `--fail-on-review-due-waivers`. |
| `compare` | repeatable `--input PATH` | `markdown`, `json` | JSON schema | Comparison is `CVSS-only` vs enriched. |
| `explain` | `--cve CVE-...` | `markdown`, `json` | JSON schema | Single-CVE detailed view. |
| `doctor` | optional local files and runtime config | `json` | JSON schema | Local environment, cache, file, waiver-health, and optional live-source diagnostics. |
| `snapshot create` | repeatable `--input PATH` | `markdown`, `json` | JSON schema | Reusable point-in-time artifact over the same prioritization pipeline as `analyze`. |
| `snapshot diff` | two snapshot JSON files | `markdown`, `json` | JSON schema | Categorizes `added`, `removed`, priority, and context changes per CVE. |
| `state init` | `--db PATH` | `json` | JSON schema | Initializes the optional local SQLite backing store used only for persisted snapshot history. |
| `state import-snapshot` | snapshot JSON file | `json` | JSON schema | Imports a saved `snapshot create --format json` artifact into the optional local SQLite state store. |
| `state history` | local SQLite DB + `--cve` | `json` | JSON schema | Returns persisted per-CVE history across imported snapshots. |
| `state waivers` | local SQLite DB | `json` | JSON schema | Shows persisted waiver lifecycle debt from the latest snapshot or full imported history. |
| `state top-services` | local SQLite DB | `json` | JSON schema | Shows repeated service pressure across imported snapshots without rerunning enrichment. |
| `rollup` | analysis JSON or snapshot JSON | `markdown`, `json` | JSON schema | Aggregates findings by `asset_id` or `asset_business_service`, keeps waiver lifecycle debt visible, and ranks buckets for remediation planning without rerunning enrichment. |
| `attack validate` | ATT&CK local files | `markdown`, `json` | No published schema yet | Validates local mapping and metadata artifacts; `ctid-json` is the preferred workflow. |
| `attack coverage` | `--input PATH` | `markdown`, `json` | No published schema yet | Uses the same input loader for CVE extraction. |
| `attack navigator-layer` | `--input PATH` | Navigator layer JSON | Navigator JSON, no local schema here | Exports a frequency-based ATT&CK Navigator layer. |
| `data status` | none | `json` | JSON schema | Cache namespace inspection plus optional local ATT&CK metadata validation. |
| `data update` | optional repeatable `--input PATH` / `--cve` | `json` | JSON schema | Cache refresh for `nvd`, `epss`, and `kev`; `table` remains the default terminal view. |
| `data verify` | optional repeatable `--input PATH` / `--cve` | `json` | JSON schema | Cache coverage, checksum, and pinned local file verification; `table` remains the default terminal view. |
| `data export-provider-snapshot` | repeatable `--input PATH` and/or `--cve` | `json` | JSON schema | Exports replayable provider data for `nvd`, `epss`, and `kev` so later analysis can run in fallback or locked snapshot mode. |
| `report html` | analysis JSON | `html` | Consumes analysis JSON contract | No live enrichment during rendering. |
| `report evidence-bundle` | analysis JSON | `zip` | Manifest schema inside bundle | Packages saved analysis JSON, regenerated HTML, Markdown summary, and optional source input copy. |
| `report verify-evidence-bundle` | evidence ZIP | `json` | JSON schema | Verifies ZIP members against the embedded manifest and reports missing, modified, unexpected, or malformed bundle content. |

## Input-format matrix

| `--input-format` | Auto-detect | `analyze` / `compare` | `attack coverage` / `navigator-layer` | Normalized provenance currently preserved | Notes |
| --- | --- | --- | --- | --- | --- |
| `cve-list` | `.txt`, `.csv` | yes | yes | `cve_id`, source line/row | Historical compatibility path. |
| `trivy-json` | JSON with `Results` | yes | yes | component, version, purl, package type, path, fix versions, target image | Default target kind is `image`. |
| `grype-json` | JSON with `matches` | yes | yes | component, version, purl, package type, path, fix versions, target image | Keeps the first artifact location as current path evidence. |
| `cyclonedx-json` | JSON with `bomFormat=CycloneDX` and vulnerabilities | yes | yes | component refs, purl, versions, dependency context when present | Used for SBOM+vuln exports, not plain BOMs without vulnerabilities. |
| `spdx-json` | JSON with `spdxVersion` | yes | yes | package names, versions, file names when available | Current support is JSON only. |
| `dependency-check-json` | JSON with `scanInfo` and `dependencies` | yes | yes | dependency path, package/file names, severity, fix/version hints where present | Current support is JSON only. |
| `github-alerts-json` | JSON array or alert-like object | yes | yes | advisory source, package context when present | Contract assumes a pinned JSON export shape, not arbitrary API responses. |
| `nessus-xml` | `.nessus` | yes | yes | host target, plugin name, service/port label, severity, source record id | Pinned Nessus XML export shape. Only resolvable CVEs are normalized. |
| `openvas-xml` | pinned OpenVAS-style `.xml` | yes | yes | host target, NVT name, severity, source record id | Prefer explicit `--input-format openvas-xml` in CI. Only resolvable CVEs are normalized. |

## Feature overlay matrix

| Feature | `analyze` | `compare` | `explain` | Notes |
| --- | --- | --- | --- | --- |
| ATT&CK enrichment | yes | yes | yes | Sources: `none`, `local-csv`, `ctid-json`. Prefer `ctid-json`; `local-csv` remains legacy compatibility only. No remote ATT&CK dependency. |
| Asset context CSV | yes | yes | yes | `target_kind` stays exact; `target_ref` supports deterministic `exact` and `glob` rules with optional `rule_id`, `match_mode`, `precedence`, and aggregated conflict reporting. |
| VEX files | yes | yes | yes | Supports OpenVEX JSON and CycloneDX VEX JSON with deterministic ranked matching, occurrence-level match provenance, aggregated conflict reporting, and visible `under_investigation` status. |
| Policy profiles | yes | yes | yes | Built-ins: `default`, `enterprise`, `conservative`. |
| Custom policy file | yes | yes | yes | YAML-defined profiles, selected by `--policy-profile`. |
| Waiver file | yes | yes | yes | YAML risk-acceptance rules mark findings as waived without deleting the underlying prioritization evidence. Optional `review_on` plus automatic near-expiry handling keep stale waivers visible. |
| Runtime config discovery | yes | yes | yes | Also applies to `doctor`, `snapshot create`, and `rollup` where relevant defaults exist. |
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
- Prefer `--summary-output` when GitHub Actions, PR automation, or local review needs a compact Markdown executive summary.
- Prefer `state import-snapshot` plus `state history|waivers|top-services` when you need repeated local review over saved snapshots rather than another live enrichment run.
- Prefer `report evidence-bundle` when a review board or release gate needs a reproducible offline artifact set from a saved analysis run.
- Prefer `report verify-evidence-bundle` before shipping or archiving an evidence ZIP outside the repository or CI workspace.
- `report html` expects an analysis JSON export, not compare JSON or explain JSON.
- `sarif` is part of the documented contract only for `analyze`.
- `data status`, `data update`, and `data verify` now publish JSON contracts via `--format json`; their Rich table layout remains human-facing.
- The optional SQLite state store is separate from the existing file cache and does not change `analyze`, `snapshot`, or `report` output semantics.
- `vuln-prioritizer.yml` is the documented runtime-config filename; `--config` and `--no-config` are the stable CLI overrides.
