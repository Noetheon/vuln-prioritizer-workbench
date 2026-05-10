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
- `state trends --format json`
- `state service-history --format json`
- `input validate --format json`
- `input inspect --format json`
- `input normalize --format json`
- `data status --format json`
- `data update --format json`
- `data verify --format json`
- `data export-provider-snapshot`
- `attack validate --format json`
- `attack coverage --format json`
- `rollup --format json`
- `analyze --format sarif`
- `analyze --summary-output <path>`
- `report workbench --input <analysis-json> --format sarif`
- `report html --input <analysis-json>`
- `report evidence-bundle --input <analysis-json>`
- `report verify-evidence-bundle --input <evidence-zip> --format json`
- `report validate-sarif --input <sarif> --format json`

Published JSON schemas in `docs/schemas/` cover:

- `analysis-report.schema.json`
- `analysis-result.v1.schema.json`
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
- `state-trends-report.schema.json`
- `state-service-history-report.schema.json`
- `input-validation-report.schema.json`
- `input-inspect-report.schema.json`
- `data-status-report.schema.json`
- `data-update-report.schema.json`
- `data-verify-report.schema.json`
- `provider-snapshot-report.schema.json`
- `attack-curated-mapping.schema.json`
- `attack-validation-report.schema.json`
- `attack-coverage-report.schema.json`
- `rollup-report.schema.json`
- `evidence-bundle-manifest.schema.json`
- `evidence-bundle-verification-report.schema.json`

`input-inspect-report.schema.json` covers both `input inspect --format json` and
the `input normalize --format json` compatibility alias.
`attack-curated-mapping.schema.json` is a local ATT&CK mapping artifact schema
for reviewed JSON or YAML-compatible curated mapping files. It is an input
contract, not a command output report. Its `confidence` field is a `low`,
`medium`, or `high` enum; the loader emits numeric confidence only internally
for compatibility with existing enrichment models.

`report html` is a secondary renderer over the analysis JSON contract. It does not define its own independent source model.
`report evidence-bundle` is a ZIP transport over the analysis JSON contract. Its published machine contract is the `manifest.json` stored inside the bundle.
`report verify-evidence-bundle` is the published integrity-report contract for saved evidence ZIP bundles.

`baseline_comparison` is additive on analysis-style payloads. It compares
CVSS-only priority bands with the enriched policy and includes priority counts,
up/down/unchanged totals, top changes with old/new rank, and a methodology
limitation stating that the view is decision support rather than absolute truth.

## JSON envelope contract

All documented JSON exports include explicit metadata or top-level version fields. Analysis-style reports keep the richer `metadata` + `attack_summary` envelope, while helper and state commands publish smaller purpose-built contracts.

Primary payload keys by command:

- `analyze`: `findings`, optional `baseline_comparison`
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
- `state trends`: `items`
- `state service-history`: `items`
- `input validate`: `summary`, `sources`, `asset_context`, and `vex`
- `input inspect` / `input normalize`: `summary`, `sources`, `unique_cves`, and normalized `occurrences`
- `data status`: `namespaces`
- `data update`: `sources`
- `data verify`: `namespaces`, plus `coverage` and `local_files`
- `attack validate`: validation counts and warning arrays
- `attack coverage`: `items`, plus ATT&CK coverage `summary`
- `rollup`: `buckets`
- `report evidence-bundle`: `manifest.json` with `files` and optional `governance_artifacts`
- `report verify-evidence-bundle`: `items`, plus `summary`

### Schema versioning

Current value:

- `1.0.0`

Consumer guidance:

- treat an unknown major version as unsupported
- tolerate additive fields on the same major version
- ignore unknown object members rather than failing on extra fields

The published JSON schemas are release validation artifacts and intentionally
tolerate additive object members through `additionalProperties: true`. Consumers
should treat same-major additive object members as tolerated and ignore fields
they do not understand.

The primary analysis-style schemas target the currently emitted version, `1.0.0`.
ATT&CK provenance fields such as `attack_mapping_file_sha256`, `attack_technique_metadata_file_sha256`, `attack_metadata_format`, and `attack_stix_spec_version` are additive metadata fields on that same major contract.
Defensive context fields such as `defensive_context_file`, `defensive_context_sources`,
`defensive_context_hits`, per-finding `defensive_contexts`, and
`provider_evidence.defensive_contexts` are additive local-context fields on the
same major contract.

Helper contracts use either an explicit envelope version or their published schema as the contract version anchor:

- `doctor`: top-level `schema_version = 1.2.0`
- `snapshot create`: `metadata.schema_version = 1.1.0`
- `snapshot diff`: `metadata.schema_version = 1.1.0`
- `state init`: `metadata.schema_version = 1.2.0`
- `state import-snapshot`: `metadata.schema_version = 1.2.0`
- `state history`: `metadata.schema_version = 1.2.0`
- `state waivers`: `metadata.schema_version = 1.2.0`
- `state top-services`: `metadata.schema_version = 1.2.0`
- `state trends`: `metadata.schema_version = 1.2.0`
- `state service-history`: `metadata.schema_version = 1.2.0`
- `input validate`: `metadata.schema_version = 1.2.0`
- `input inspect` / `input normalize`: `metadata.schema_version = 1.3.0`
- `data status`, `data update`, and `data verify`: `metadata.schema_version = 1.2.0`
- `data export-provider-snapshot`: `metadata.schema_version = 1.2.0`
- `rollup`: `metadata.schema_version = 1.2.0`
- `report verify-evidence-bundle`: `metadata.schema_version = 1.2.0`
- `attack validate` and `attack coverage`: published schemas define their current stable JSON shape

## Semantic contract

The field names are only part of the contract. The meaning of several fields matters for downstream consumers.

### Base priority

`priority_label` is the primary priority decision.

Current rule:

- it is derived from `CVSS + EPSS + KEV`
- ATT&CK is contextual
- asset context is contextual for the base priority label and contributes only to the operational queue score
- defensive context is contextual
- VEX can suppress a finding from the default visible list and may set `priority_state` to `Suppressed` or `Fixed`

`priority_state` is the effective lifecycle-aware priority enum. Allowed values are
`Critical`, `High`, `Medium`, `Low`, `Suppressed`, `Accepted`, and `Fixed`.
Active findings use the same state as `priority_label`; VEX and waiver evidence can
move the state to a governance value while keeping the base label and drivers
visible.

`operational_score` is an additive integer from 0 to 100. It is computed from
explicit contributions for base priority, KEV, EPSS/CVSS thresholds, asset
exposure, production context, criticality, and active occurrence count, plus
explicit zero-point routing context for owner and business service, then clamped
to the 0-100 range. `operational_score_reasons` lists the matched rules and
clamp result. Unknown asset context is emitted as an explicit neutral reason and
must not be interpreted as safe or lower-risk.

`explanation` is the structured "why this priority?" object on generated
findings. It includes stable `reason_codes`, detailed `reasons[]` entries with
source, signal, value and threshold, human-readable text, data-quality notes, and
the recommended action. Missing CVSS or EPSS data is represented as a note rather
than hidden inside the narrative. Asset context appears as an explicit
`asset.context` reason when exposure, environment, criticality, service, or owner
data is present; unknown occurrence context appears as an `asset.context_unknown`
warning note. The Workbench `/api/v1/findings/{finding_id}/explain`
endpoint exposes this object as `decision_explanation` while retaining the raw
finding payload under `explanation`.

### ATT&CK context

ATT&CK fields are optional enrichment.

Current guarantees:

- ATT&CK is local-file sourced only through `ctid-json`, reviewed
  `local-curated`, or legacy `local-csv`
- no heuristic or LLM-generated CVE-to-ATT&CK mapping is performed
- `attack_relevance` is a contextual, explainable helper label produced locally by this CLI
- absence of ATT&CK data is represented as unmapped context, not guessed context
- JSON findings include an additive `attack_context` object with mapped state,
  source/version metadata, techniques, tactics, mappings, and curated
  `confidence` when available
- unmapped findings use `mapped=false`, `source=none`, `confidence=null`, and
  empty `techniques`, `tactics`, and `mappings` arrays
- low-confidence ATT&CK context is retained for review and surfaced in
  explanations as `attack.low_confidence`; it does not change the hard base
  priority label, rank, or priority drivers

### Remediation guidance

Current remediation contract:

- `remediation` is additive structured guidance, not a hidden scoring input
- `recommended_action` is rendered from `remediation` plus the current priority label
- remediation evidence is derived from occurrence-level package/component signals, not only the aggregated `fix_versions` union
- `decision_guidance` is an additive structured recommendation object with a
  template (`patch`, `mitigate`, `monitor`, `review`, or `waiver`), SLA target,
  business-impact block, management-readable decision statement, visibility
  rule, and `wording_policy = defensive_no_exploit_steps`
- Accepted, suppressed, and fixed findings remain visible as governance states;
  the generator changes their recommendation template and SLA, but does not hide
  them as completed remediation

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
- OpenVEX product and subcomponent PURLs may be supplied as `@id`, `purl`, or `identifiers.purl`
- CycloneDX VEX uses `vulnerabilities[].id`, `vulnerabilities[].analysis.state`,
  and `vulnerabilities[].affects[].ref`; `affects[].ref` must resolve to a
  component `bom-ref` or be a direct PURL
- CycloneDX VEX states map as follows: `exploitable` and `affected` become
  `affected`; `not_affected` and `false_positive` become `not_affected`;
  `resolved`, `resolved_with_pedigree`, and `fixed` become `fixed`;
  `in_triage` becomes `under_investigation`
- unsupported CycloneDX VEX fields such as ratings, advisories, `analysis.detail`,
  services, dependencies, and non-`affects` scope are ignored for matching but
  the source document remains stored as upload evidence
- exact text in `vex_justification` and `vex_action_statement` is informative, not enum-stable

### Asset context semantics

Current asset-context contract:

- asset context is evaluated per occurrence, not per CVE aggregate
- `target_kind` stays exact
- `target_ref` supports deterministic `exact`, `contains`, `regex`, and compatibility `glob` matching with precedence and CSV row tie-breaks
- CSV files require `target_kind`, `asset_id`, and either `target_ref` or its `asset_ref` alias; see [Asset Context CSV](asset-context-csv.md)
- unknown `criticality`, `exposure`, and `environment` enum values are ignored with warnings, while invalid `match_mode`, regex syntax, or non-integer `precedence` values fail validation
- `input validate --format json` exposes `asset_context.exact_rules`, `contains_rules`, `regex_rules`, and `glob_rules`
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

### Provider freshness gates

Current provider freshness contract:

- `--max-provider-age-hours` is additive on `analyze`, `compare`, and `snapshot create`
- `--fail-on-stale-provider-data` returns exit code `1` after writing requested output when provider data is stale
- live lookups use the current run timestamp for freshness
- locked provider-snapshot replay uses the snapshot `generated_at` timestamp for selected snapshot sources
- analysis-style metadata includes provider snapshot identity when available:
  `provider_snapshot_id`, `provider_snapshot_hash`, `provider_snapshot_file`, and
  `provider_snapshot_sources`
- analysis-style metadata may include `provider_freshness`, `max_provider_age_hours`, `provider_stale`, and `provider_stale_sources`

### Provider enrichment service

Current provider service contract:

- built-in NVD, EPSS, and KEV providers can be adapted to the shared
  `ProviderEnrichmentClient.enrich(cve_ids, **kwargs)` interface
- provider snapshots use the additive `provider-snapshot.v1.json` format marker
  in `metadata.snapshot_format`, plus `snapshot_id`, `source_hashes`, and
  per-source `source_metadata`
- NVD uses the CVE API 2.0 per requested CVE, sends an optional API key only
  through the configured request header, redacts configured key values from
  warnings, and degrades to cache or empty records instead of aborting analysis
- provider failures degrade into `ProviderStatus` and data-quality flags before
  optional CI gates decide whether to fail the process
- canonical provider data-quality codes are additive and include
  `nvd_missing`, `nvd_cvss_missing`, `epss_missing`, `epss_outdated`,
  `kev_unavailable`, `snapshot_locked`, and `provider_error`; legacy generic
  codes such as `provider_failure`, `provider_missing_data`, `stale_cache`, and
  `provider_warning` may still be emitted for compatibility
- NVD records with provider metadata but no CVSS base score/version add an
  `nvd_cvss_missing` data-quality flag with the affected `cve_id`
- KEV provider data includes CISA catalog details such as
  `vulnerability_name`, `vendor_project`, `product`, `date_added`, `due_date`,
  and `required_action` when present in JSON, CSV, cache, or locked snapshot
  sources
- `ProviderStatus` includes `source`, `last_sync`, `cache_hit`, `cache_miss`,
  cache counters, stale-cache counters, network/failure counters, and
  `data_quality_flags`
- provider snapshot metadata includes `source_hashes`, a map from selected
  provider source to the local cache namespace SHA-256 checksum or `null`
- Workbench exposes provider snapshot list/detail/download/import API routes;
  import accepts only explicit `provider-snapshot.v1.json` snapshots containing
  `metadata.snapshot_format` and `metadata.source_metadata`, and evidence
  bundles include the resolved provider snapshot JSON as
  `provider/provider-snapshot.json` when a replay snapshot is part of the run
- analysis-style metadata may include `provider_data_quality_flags`, keyed by
  source, when recoverable provider problems such as missing EPSS records,
  stale cache fallback, or provider warnings were observed; individual
  findings expose scoped `data_quality_flags` and `data_quality_confidence`
  (`high`, `medium`, `low`) so missing data cannot silently collapse priority
  to Low without visible evidence
- cache contract metadata includes namespace, raw key template, TTL seconds,
  and whether expired cache may be used on provider failure
- required tests for this contract use versioned fixtures under
  `data/provider_contract_fixtures/v1`, fake providers, or monkeypatching, not
  live provider APIs; live provider smoke tests are marked `live_network` and
  skipped unless explicitly enabled

### Defensive context semantics

Current defensive-context contract:

- `--defensive-context-file` reads a local JSON file only; the CLI does not fetch OSV, GHSA, Vulnrichment, or SSVC records live
- allowed local overlay sources are normalized as `osv`, `ghsa`, `vulnrichment`, and `ssvc`
- defensive context is informational evidence attached to findings, provider evidence, provider snapshots, and Workbench payloads
- `defensive_context_file`, `defensive_context_sources`, and `defensive_context_hits` summarize local overlay usage in analysis-style metadata
- `defensive_contexts` on findings and provider snapshot items contains the local overlay records used for review and locked replay
- defensive context does not change `priority_label`, `priority_rank`, operational rank, or base scoring

### Evidence bundle governance artifacts

Current evidence-bundle governance additions:

- governance bundle members are additive ZIP members under `governance/`
- supported member paths are `governance/rollups.json`, `governance/waivers.json`, `governance/vex-summary.json`, `governance/asset-context.json`, and `governance/detection-coverage.json`
- these members are included only when the corresponding governance source payload is available
- `manifest.json` may include an additive `governance_artifacts` array
- each `governance_artifacts[]` item contains `bundle_path`, `kind`, and `sha256`
- `bundle_path` is the ZIP member path, `kind` identifies the governance artifact type, and `sha256` is the checksum of that member content
- consumers should verify governance artifacts against their manifest SHA-256 entries and ignore unknown future governance artifact kinds

### Workbench API additions

Workbench API changes are versioned under the active `/api/v1` backend:

- `POST /api/v1/api-tokens/`, `GET /api/v1/api-tokens/`, and `DELETE /api/v1/api-tokens/{token_id}` manage Workbench service tokens; the create response is the only response that includes the cleartext token, and metadata responses include `expires_at`
- `ApiTokenCreate.expires_at` is optional and must be in the future when supplied; omitted values use `API_TOKEN_DEFAULT_EXPIRE_DAYS` from the active Workbench settings, which defaults to 90 days
- non-admin Workbench service tokens require `project_id` and are limited to that project; `admin` tokens are global, root-equivalent automation credentials and must not carry `project_id`
- Workbench service-token scopes are enforced by dependency: `read` covers project/run/finding/provider/waiver reads, `write` covers project-scoped project/asset/waiver mutations, `import` covers `/api/v1/projects/{project_id}/imports`, `report` covers report creation/download/verification, and `admin` covers token lifecycle, project creation, and satisfies all scoped dependencies; revoked, expired, or inactive-user tokens are rejected
- the current Workbench access model is owner/superuser plus project-scoped non-admin service tokens; project membership tables and project-admin roles are not implemented in this local-first release
- browser JWTs include a persisted session identifier; `/api/v1/login/logout` revokes the active session, and API dependencies reject revoked or expired sessions before returning a user
- `/api/v1/audit/events` lists redacted audit events for administrators, and `/api/v1/audit/sessions` lists browser session metadata without JWT IDs, token hashes, or cleartext secrets
- configured rate limits return HTTP 429 with `Retry-After` for excessive API, login, or invalid bearer-token attempts
- `python -m app.core.retention --dry-run` previews configured audit/session/revoked-token cleanup, while `python -m app.core.retention` applies cleanup and writes a retention audit event
- `POST /api/v1/projects/{project_id}/imports` accepts a JWT-gated Workbench upload, validates input type, extension, MIME hint, filename, and upload size, persists the uploaded file under the configured import upload root, and records upload SHA-256 plus structured `parse_errors` in the returned `AnalysisRun`
- Workbench imports optionally accept `provider_snapshot_file` and `locked_provider_data` form fields; when no explicit snapshot is supplied, local deterministic demo snapshot replay is used only when `DEMO_PROVIDER_SNAPSHOT_ENABLED=true` and the configured snapshot exists
- Workbench imports use `cve_baseline_with_occurrence_overlays` semantics: the shared parse/enrich/score/explain engine computes the baseline decision per CVE, while occurrence, asset, VEX, waiver, and lifecycle overlays drive persistence and per-finding context; stored findings include the effective priority, priority rank, risk score, operational rank, KEV/EPSS/CVSS signals, lifecycle flags, rationale, recommended action, and structured `explanation_json`
- Workbench import analysis failures after the upload run is created mark the run `failed`, add `summary_json.analysis_error` and `error_json.analysis_error`, and do not expose partially persisted findings as successful imports
- `GET /api/v1/projects/{project_id}/runs` and `GET /api/v1/projects/{project_id}/runs/` list visible Workbench runs
- `GET /api/v1/runs/{run_id}` returns the raw persisted Workbench run for a visible project
- `GET /api/v1/runs/{run_id}/summary` returns a UI-oriented summary with stable `analysis_decision_scope`, `persistence_scope`, `created_findings`, `updated_findings`, `ignored_lines`, `occurrence_count`, `finding_count`, `parse_errors`, `import_job`, `input_upload`, `dedup_summary`, `counts_by_priority`, `kev_hits`, `provider_snapshot_id`, and `provider_degraded` fields
- `import_job` and provider `latest_update_job` values are execution metadata, not asynchronous worker handles; current import/provider jobs execute in the request path, expose `execution_mode: "request"`, and report creation is request/response artifact generation
- `GET /api/v1/findings/{finding_id}/explain` returns the stored decision explanation for a visible Workbench finding, including decision guidance, provider evidence, data-quality fields, rationale, and recommended action; it returns 422 when the finding exists but no decision explanation has been persisted yet
- `GET /api/v1/projects/{project_id}/summary` returns a dashboard-oriented decision summary with finding counts, priority/status buckets, provider-signal hit counts, latest run status, and latest run summary
- `GET /api/v1/projects/{project_id}/compare/cvss-only` returns the CVSS-only baseline comparison for stored Workbench findings, using the same methodology payload as the core decision engine. Full per-finding `comparisons` rows are omitted by default; callers that need them must pass `include_comparisons=true`, and projects above `DECISION_API_MAX_FINDINGS` are rejected for this endpoint.
- `GET /api/v1/providers/status` returns an authenticated provider-status envelope for the React status card, including `status`, `snapshot`, `sources`, `latest_update_job`, `cache_dir`, `snapshot_dir`, `warnings`, `last_sync`, `last_error`, `cache_age_seconds`, and `snapshot_mode`
- `POST /api/v1/runs/{run_id}/reports` accepts `markdown`, `html`, `json`, `csv`, `zip`, `attack-navigator`, and `sarif` for completed visible Workbench runs. JSON exports use `analysis-result.v1.json` with `project`, `analysis_run`, `provider_snapshot`, `findings`, `explanations`, optional `governance_rollups`, and optional `detection_coverage`. CSV exports use `findings.csv` with stable spreadsheet-safe finding columns. SARIF exports use `results.sarif` with SARIF 2.1.0, CVE-addressable rule/result IDs, priority/CVSS-derived levels and `security-severity`, stable `vuln-prioritizer/v1` fingerprints shared with CLI SARIF, and HTTP(S) references including the canonical NVD CVE URL. Fingerprint material is CVE ID, canonical path or `target_kind:target_ref`, Package URL when present or component label otherwise, and asset identity; it excludes priority, score, governance state, run/report IDs, timestamps, and Workbench persistence `dedup_key`. `attack-navigator` exports `attack-navigator-layer.json` with Navigator v4.5-compatible `techniques`, `techniqueID`, risk score, comments, and metadata; `attack_filter` accepts `all`, `critical-high`, `kev`, and the `no-coverage` placeholder. ZIP exports use `evidence-bundle.zip` with `manifest.json`, `analysis.json`, `technical.md`, `executive.html`, `provider-snapshot.json`, optional `attack-navigator-layer.json`, optional `governance/rollups.json`, `governance/waivers.json`, `governance/vex-summary.json`, `governance/asset-context.json`, and `governance/detection-coverage.json`, per-file SHA-256 entries, input hashes when available, and redaction of sensitive/local-path fields.
- `POST /api/v1/reports/{report_id}/verify` verifies a visible Workbench `evidence-bundle.zip` report without extracting ZIP members. It validates the stored artifact path and report SHA-256 before returning the same `metadata`, `summary`, and `items` shape as `report verify-evidence-bundle --format json`; non-bundle reports return 422.
- `POST /api/v1/projects/{project_id}/github/issues/preview` prepares GitHub issue markdown for selected `finding_ids` or the top-ranked visible findings. Each item includes `finding_id`, `cve_id`, title, labels, milestone, duplicate key, evidence references, and a redacted Markdown body with priority, rationale, remediation, and Workbench/NVD evidence links. Preview requires report scope and writes a redacted `github_issue.preview` audit event without issue body content or token material. `POST /api/v1/projects/{project_id}/github/issues/export` requires admin scope, defaults to `dry_run: true`, and real creation requires `dry_run: false`, `repository: "owner/name"`, and an explicit token environment variable. Export writes redacted `github_issue.export` audit events for dry-run, duplicate skip, successful create summaries, token setup failures, GitHub upstream status failures, and network failures. Created duplicate keys are persisted per project/repository so repeated successful exports return `skipped_duplicate`; failed create reservations are removed before the failure audit is committed so retries are not blocked by empty local rows.
- Workbench import summaries may include `defensive_context_sources` and `defensive_context_hits`, and finding/detail/report payloads may include per-finding `defensive_contexts` copied from local defensive context uploads
- `--fail-on-expired-waivers` and `--fail-on-review-due-waivers` are opt-in enforcement hooks

Workbench import parse errors use this additive shape in `parse_errors`:

- `input_type`: normalized import type such as `cve-list`
- `filename`: sanitized uploaded filename when available
- `message`: parser-facing error text suitable for display
- `error_type`: importer exception class name
- `line`: 1-based input line number when the parser error includes one
- `field`: logical field when inferable, for example `cve_id`
- `value`: rejected value when inferable from the parser message

Consumers should treat `line`, `field`, and `value` as optional and preserve
unknown additive members.

### Parser and provider extension SDK

The extension SDK is a static local contract:

- input parser definitions are explicit local `InputParserDefinition` records with fixture metadata
- provider definitions are explicit local `ProviderDefinition` records with a `fetch_many` protocol
- SDK helpers validate names, duplicate registration, fixture metadata, and remote-code-loading flags
- the SDK does not discover Python entry points, import user-supplied plugin paths, call subprocesses, or fetch executable code from URLs

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
- `state trends`: `table`, `json`
- `state service-history`: `table`, `json`
- `input validate`: `table`, `json`
- `input inspect`: `table`, `json`
- `input normalize`: `table`, `json`
- `rollup`: `table`, `markdown`, `json`
- `attack validate`: `table`, `markdown`, `json`
- `attack coverage`: `table`, `markdown`, `json`
- `attack navigator-layer`: JSON file output
- `data status`: `table`, `json`
- `data update`: `table`, `json`
- `data verify`: `table`, `json`
- `data export-provider-snapshot`: JSON file output
- `report workbench`: `json`, `markdown`, `html`, `csv`, `sarif`
- `report html`: HTML file output
- `report evidence-bundle`: ZIP file output containing `analysis.json`, `report.html`, `summary.md`, `manifest.json`, and optional `governance/rollups.json`, `governance/waivers.json`, `governance/vex-summary.json`, `governance/asset-context.json`, and `governance/detection-coverage.json`
- `report verify-evidence-bundle`: `table` and `json`
- `report validate-sarif`: `table` and `json`

Important boundary:

- `table` is a terminal view and must not be combined with `--output`
- `sarif` is a documented export for `analyze` and saved analysis JSON rendered
  through `report workbench`
- Workbench report creation also exposes SARIF as `results.sarif`
  through `POST /api/v1/runs/{run_id}/reports`
- SARIF `partialFingerprints["vuln-prioritizer/v1"]` are report identities,
  not Workbench database `dedup_key` values
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

- breaking machine-readable changes must update the relevant schema version or published schema contract
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
- HTML, Markdown, and terminal wording for `doctor`, `snapshot diff`, `state history`, `state waivers`, `state top-services`, and `rollup`
- exact ZIP layout details inside `report evidence-bundle` beyond the published `manifest.json` contract
- cryptographic signing or provenance attestation for evidence bundles; current verification checks ZIP members against the embedded manifest only

The SQLite file format itself is also not a published contract. The stable automation surface for the optional local state store is the documented JSON output of the `state` subcommands, not the internal table layout.

Those surfaces are useful, but they should not be treated as strict automation contracts unless they are later given their own published schemas.
