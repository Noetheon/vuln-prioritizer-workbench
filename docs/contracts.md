# Contracts

## Scope

This document describes the current public contract for the implemented CLI and report surfaces. It is intentionally based on the code that exists today, not on roadmap-only behavior.

The project exposes three kinds of interfaces:

- CLI flags and exit behavior
- machine-readable exports
- human-readable reports

The strongest contract today is the JSON export surface.

## Public machine-readable surfaces

The following outputs are the current documented machine interfaces:

- `analyze --format json`
- `compare --format json`
- `explain --format json`
- `doctor --format json`
- `snapshot create --format json`
- `snapshot diff --format json`
- `state init --format json`
- `state import-snapshot --format json`
- `state history --format json`
- `state waivers --format json`
- `state top-services --format json`
- `data status --format json`
- `data update --format json`
- `data verify --format json`
- `data export-provider-snapshot`
- `rollup --format json`
- `analyze --format sarif`
- `analyze --summary-output <path>`
- `report html --input <analysis-json>`
- `report evidence-bundle --input <analysis-json>`
- `report verify-evidence-bundle --input <evidence-zip> --format json`

Published JSON schemas in `docs/schemas/` cover:

- `analysis-report.schema.json`
- `compare-report.schema.json`
- `explain-report.schema.json`
- `doctor-report.schema.json`
- `snapshot-report.schema.json`
- `snapshot-diff-report.schema.json`
- `state-init-report.schema.json`
- `state-import-report.schema.json`
- `state-history-report.schema.json`
- `state-waivers-report.schema.json`
- `state-top-services-report.schema.json`
- `data-status-report.schema.json`
- `data-update-report.schema.json`
- `data-verify-report.schema.json`
- `provider-snapshot-report.schema.json`
- `rollup-report.schema.json`
- `evidence-bundle-manifest.schema.json`
- `evidence-bundle-verification-report.schema.json`

`report html` is a secondary renderer over the analysis JSON contract. It does not define its own independent source model.
`report evidence-bundle` is a ZIP transport over the analysis JSON contract. Its published machine contract is the `manifest.json` stored inside the bundle.
`report verify-evidence-bundle` is the published integrity-report contract for saved evidence ZIP bundles.

## JSON envelope contract

All documented JSON exports include explicit metadata or top-level version fields. Analysis-style reports keep the richer `metadata` + `attack_summary` envelope, while helper and state commands publish smaller purpose-built contracts.

Primary payload keys by command:

- `analyze`: `findings`
- `compare`: `comparisons`
- `explain`: `finding`, plus `nvd`, `epss`, `kev`, `attack`, and `comparison`
- `doctor`: `checks`
- `snapshot create`: `findings`
- `snapshot diff`: `items`, plus `summary`
- `state init`: `summary`
- `state import-snapshot`: `summary`
- `state history`: `items`
- `state waivers`: `items`
- `state top-services`: `items`
- `data status`: `namespaces`
- `data update`: `sources`
- `data verify`: `namespaces`, plus `coverage` and `local_files`
- `rollup`: `buckets`
- `report evidence-bundle`: `manifest.json` with `files`
- `report verify-evidence-bundle`: `items`, plus `summary`

### `metadata.schema_version`

Every documented JSON export includes `metadata.schema_version`.

Current value:

- `1.0.0`

Consumer guidance:

- treat an unknown major version as unsupported
- tolerate additive fields on the same major version
- ignore unknown object members rather than failing on extra fields

The bundled schemas target the currently emitted version, `1.0.0`.

New v1.1 helper contracts use their own envelope versions:

- `doctor`: top-level `schema_version = 1.2.0`
- `snapshot create`: `metadata.schema_version = 1.1.0`
- `snapshot diff`: `metadata.schema_version = 1.1.0`
- `state init`: `metadata.schema_version = 1.2.0`
- `state import-snapshot`: `metadata.schema_version = 1.2.0`
- `state history`: `metadata.schema_version = 1.2.0`
- `state waivers`: `metadata.schema_version = 1.2.0`
- `state top-services`: `metadata.schema_version = 1.2.0`
- `rollup`: `metadata.schema_version = 1.2.0`
- `report verify-evidence-bundle`: `metadata.schema_version = 1.2.0`

## Semantic contract

The field names are only part of the contract. The meaning of several fields matters for downstream consumers.

### Base priority

`priority_label` is the primary priority decision.

Current rule:

- it is derived from `CVSS + EPSS + KEV`
- ATT&CK is contextual
- asset context is contextual
- VEX can suppress a finding from the default visible list, but it does not create a new opaque risk score

### ATT&CK context

ATT&CK fields are optional enrichment.

Current guarantees:

- ATT&CK is local-file sourced only
- no heuristic or LLM-generated CVE-to-ATT&CK mapping is performed
- `attack_relevance` is a contextual, explainable helper label produced locally by this CLI
- absence of ATT&CK data is represented as unmapped context, not guessed context

### Remediation guidance

Current remediation contract:

- `remediation` is additive structured guidance, not a hidden scoring input
- `recommended_action` is rendered from `remediation` plus the current priority label
- remediation evidence is derived from occurrence-level package/component signals, not only the aggregated `fix_versions` union

### Provenance

`provenance` is an aggregated per-CVE view over occurrence-level input evidence.

Current meaning:

- `occurrence_count` counts total known occurrences for the CVE
- `active_occurrence_count` excludes VEX-suppressed occurrences
- `suppressed_occurrence_count` counts occurrences suppressed by VEX
- `source_formats`, `components`, `affected_paths`, `fix_versions`, and `targets` are deduplicated summaries
- `occurrences` contains the raw normalized occurrence list used for aggregation

### VEX semantics

Current VEX contract:

- VEX is evaluated per occurrence, not per naked CVE string alone
- matching is deterministic and ranked by specificity before file order
- `suppressed_by_vex` means all known occurrences are suppressed
- `under_investigation` remains visible
- exact text in `vex_justification` and `vex_action_statement` is informative, not enum-stable

### Asset context semantics

Current asset-context contract:

- asset context is evaluated per occurrence, not per CVE aggregate
- `target_kind` stays exact
- `target_ref` supports deterministic `exact` and `glob` matching with precedence and CSV row tie-breaks
- occurrence metadata exposes the winning asset rule when one matched

### Waiver semantics

Current waiver contract:

- waivers are explicit local YAML rules, not implicit suppressions
- a waived finding remains prioritized and explainable unless `--hide-waived` is set
- `waived_count` reports governance state even when waived findings are hidden from the default visible list
- waived findings surface `waived`, `waiver_status`, `waiver_reason`, `waiver_owner`, `waiver_expires_on`, and, where relevant, `waiver_scope`
- expired waivers are reported as lifecycle context and do not silently remain active
- `review_on` is an optional waiver-file field; without it, waivers become review-due automatically as expiry approaches
- `waiver_review_due_count` and `expired_waiver_count` summarize lifecycle state in analysis-style metadata
- `--fail-on` ignores waived findings so governance exceptions do not fail a pipeline by themselves
- `--fail-on-expired-waivers` and `--fail-on-review-due-waivers` are opt-in enforcement hooks

Current rollup additions:

- `waived_count` counts waived findings per bucket
- `waiver_review_due_count` and `expired_waiver_count` keep waiver debt visible in rollup buckets
- `actionable_count` separates active remediation work from total findings
- `owners` summarizes dominant asset owners and waiver owners contributing to that bucket
- `top_candidates` exposes structured per-bucket “patch these first” findings
- `rank_reason` and `context_hints` explain why a bucket ranks where it does
- `recommended_actions` summarizes the most common remediation actions in that bucket

### Context fields

`context_summary` and `context_recommendation` are explanatory fields.

Current guarantee:

- they do not silently replace `priority_label`
- they may change wording between releases without a schema break

## CLI contract

### Supported format combinations

The public combinations currently intended for use are:

- `analyze`: `table`, `markdown`, `json`, `sarif`
- `compare`: `table`, `markdown`, `json`
- `explain`: `table`, `markdown`, `json`
- `doctor`: `table`, `json`
- `snapshot create`: `markdown`, `json`
- `snapshot diff`: `table`, `markdown`, `json`
- `state init`: `table`, `json`
- `state import-snapshot`: `table`, `json`
- `state history`: `table`, `json`
- `state waivers`: `table`, `json`
- `state top-services`: `table`, `json`
- `rollup`: `table`, `markdown`, `json`
- `attack validate`: `table`, `markdown`, `json`
- `attack coverage`: `table`, `markdown`, `json`
- `attack navigator-layer`: JSON file output
- `data status`: `table`, `json`
- `data update`: `table`, `json`
- `data verify`: `table`, `json`
- `report html`: HTML file output
- `report evidence-bundle`: ZIP file output containing `analysis.json`, `report.html`, `summary.md`, and `manifest.json`
- `report verify-evidence-bundle`: `table` and `json`

Important boundary:

- `table` is a terminal view and must not be combined with `--output`
- `sarif` is a documented export only for `analyze`
- `analyze --summary-output` is a Markdown sidecar derived from the same in-memory analysis payload and does not replace the JSON contract

### Runtime config

The CLI now supports a project-level runtime config file:

- canonical filename: `vuln-prioritizer.yml`
- auto-discovery walks upward from the current working directory
- `--config PATH` overrides discovery
- `--no-config` disables discovery
- precedence is built-in defaults < runtime config < explicit CLI flags

The optional SQLite state store is intentionally separate from runtime config discovery today. It is an explicit local backing-store choice made via `state ... --db PATH`, not an implicit backend change for `analyze`, `snapshot`, `rollup`, or `report`.

### Exit behavior

Current command behavior for the main flows:

- `0`: successful execution
- `1`: a no-result or policy-triggered failure condition, for example `--fail-on` matched findings or `explain` could not produce a visible finding
- `2`: input validation failure

`doctor` follows the same exit taxonomy and uses:

- `0`: all checks are `ok`
- `1`: one or more checks are `degraded` or `error`
- `2`: invalid CLI or runtime-config input

Consumers should treat warning text as informational and not parse it as a stable error taxonomy.

## Compatibility and deprecation policy

This repository documents its public contract explicitly, so the compatibility policy stays conservative and explicit even as new helper commands are added.

### JSON compatibility

- breaking machine-readable changes must update `metadata.schema_version`
- additive fields on the same major version are allowed
- narrative fields such as `rationale`, `recommended_action`, `context_summary`, `context_recommendation`, and warning strings are not text-stable parsing targets

### CLI compatibility

- existing documented flags are intended to remain stable where practical
- removals or renames should be called out in release notes
- compatibility aliases may remain even when a newer flag exists

Current compatibility alias:

- `--offline-attack-file` remains the legacy local-CSV ATT&CK path alias; `ctid-json` is the preferred ATT&CK mode for new usage

### Doctor contract notes

`doctor` is the supported first troubleshooting command for local setup and source reachability.

Current guarantees:

- each check includes a stable machine-oriented `check_id`
- each check includes explicit `scope`, `category`, and `status`
- `status` is one of `ok`, `degraded`, or `error`
- the top-level `summary` reports `overall_status` plus status counts for automation
- live-only checks appear only when `--live` is enabled

### Non-contract surfaces

The following are intentionally not covered by the published JSON schemas:

- terminal table layout
- Markdown table layout
- wording of warnings and recommendation text
- undocumented JSON payloads from helper commands such as `attack validate` and `attack coverage`
- HTML, Markdown, and terminal wording for `doctor`, `snapshot diff`, `state history`, `state waivers`, `state top-services`, and `rollup`
- exact ZIP layout details inside `report evidence-bundle` beyond the published `manifest.json` contract
- cryptographic signing or provenance attestation for evidence bundles; current verification checks ZIP members against the embedded manifest only

The SQLite file format itself is also not a published contract. The stable automation surface for the optional local state store is the documented JSON output of the `state` subcommands, not the internal table layout.

Those surfaces are useful, but they should not be treated as strict automation contracts unless they are later given their own published schemas.
