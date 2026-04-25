# Workbench ATT&CK Methodology

Current state: this page describes the local Workbench ATT&CK contract reviewed on 2026-04-25. It is not an unshipped milestone plan. It complements the CLI ATT&CK methodology by documenting the implemented API, UI/report, and evidence behavior.

## Source Contract

Workbench ATT&CK context uses CTID Mappings Explorer JSON as the canonical source for CVE-to-ATT&CK mappings.

- CTID JSON is the only canonical source for Workbench CVE-to-ATT&CK mapping decisions.
- Local CSV mapping remains legacy CLI compatibility and is not the Workbench source of record.
- Imported technique metadata enriches names, tactics, URLs, STIX spec/version metadata, and deprecation state; it does not create new CVE mappings.
- Pinned ATT&CK STIX bundles are technique metadata snapshots only. They are not CVE-to-technique mapping sources.
- CTID-enabled imports record source provenance in run and finding context: source kind, source path, source checksum, ATT&CK version/domain metadata when available, and mapped-CVE counts.
- CVEs absent from the selected CTID source are stored as unmapped. Enabling `ctid-json` without the required mapping file fails import validation instead of falling back to inferred mappings.

## No Generated Mapping

Workbench ATT&CK enrichment is evidence-based and deterministic.

- Do not infer CVE-to-technique links from CVE descriptions, CWE IDs, vendor names, product names, KEV titles, exploit text, or EPSS rank.
- Do not use LLM-generated mappings.
- Do not use fuzzy matching, keyword matching, or tactic guesses to fill CTID gaps.
- Do not silently promote analyst notes into canonical ATT&CK mappings.
- If a CVE is absent from the CTID JSON source, report it as unmapped.

Analyst annotations are outside the current Workbench contract. If added later, they need separate storage and display from CTID mappings.

## Priority Boundary

ATT&CK is a contextual threat-rank and reporting layer. It is not part of the base priority model.

The base priority remains transparent and rule-based from CVSS, EPSS, and CISA KEV. ATT&CK context can explain exposure paths, likely attacker objectives, dashboard grouping, and management reporting, but it does not silently change `priority`, `priority_rank`, or the published base priority rationale.

The Workbench exposes ATT&CK context separately through fields such as `attack_mapped`, `attack_relevance`, and `threat_context_rank`, plus full finding TTP context. These values are derived from imported CTID mapping type, tactic, technique metadata, and documented local rules. Reports and UI present them as triage context, not as the base remediation priority.

## Current API Surface

The current Workbench API preserves project, import, finding, report, and evidence endpoints while adding ATT&CK context through stable response fields and dedicated ATT&CK endpoints.

- `POST /api/projects/{project_id}/imports` accepts `attack_source=ctid-json`, `attack_mapping_file`, and `attack_technique_metadata_file` values rooted in the configured ATT&CK artifact directory.
- `GET /api/analysis-runs/{run_id}` and `GET /api/runs/{run_id}/summary` include ATT&CK summary fields such as `attack_enabled`, `attack_mapped_cves`, `attack_source`, `attack_version`, `attack_domain`, `attack_mapping_file_sha256`, `attack_technique_metadata_file_sha256`, `attack_metadata_format`, and `attack_stix_spec_version`.
- `GET /api/projects/{project_id}/findings` includes per-finding `attack_mapped` and `threat_context_rank` while keeping base priority fields separate.
- `GET /api/findings/{finding_id}` returns the base finding detail and the same high-level ATT&CK flags. Full CTID-backed TTP context lives at `GET /api/findings/{finding_id}/ttps`.
- `GET /api/findings/{finding_id}/ttps` returns source provenance, source and metadata hashes, ATT&CK version/domain, `attack_relevance`, `threat_context_rank`, review status, tactics, techniques, and mapping payloads for the finding.
- `GET /api/projects/{project_id}/attack/top-techniques` returns project-level technique rollups from persisted finding ATT&CK context.
- `GET /api/analysis-runs/{run_id}/attack/navigator-layer` returns a Navigator layer from CTID-backed mapped techniques for the run.
- `POST /api/projects/{project_id}/detection-controls/import` and `GET /api/projects/{project_id}/detection-controls` manage defensive detection-control coverage records.
- `GET /api/projects/{project_id}/attack/coverage-gaps`, `GET /api/projects/{project_id}/attack/coverage-gap-navigator-layer`, and `GET /api/projects/{project_id}/attack/techniques/{technique_id}` expose coverage gaps and technique detail without describing offensive procedures.
- Report and evidence endpoints preserve ATT&CK context in generated artifacts without weakening download path and checksum validation.

## Current UI and Report Surface

The Workbench UI makes ATT&CK useful for triage without presenting it as a hidden score.

- Import flows accept local CTID mapping and technique metadata artifacts when ATT&CK context is enabled.
- Dashboard and findings views surface mapped ATT&CK context separately from the base priority column.
- Finding detail and TTP views show CTID mapping evidence, tactics, techniques, mapping type, source checksum, metadata checksum, and explicit unmapped states.
- "Why this priority?" remains separate from ATT&CK context so users can see that CVSS, EPSS, and KEV still drive the base priority.
- Detection-control and coverage-gap views describe defensive coverage status and recommended defensive follow-up.
- Reports and generated artifacts include ATT&CK context only as optional, provenance-backed context.

## Current Evidence Artifacts

Evidence artifacts make ATT&CK provenance auditable.

- `analysis.json`: per-finding ATT&CK fields, CTID-backed mappings, source provenance, ATT&CK metadata, and unmapped state.
- Generated Markdown/HTML/JSON/CSV/SARIF reports: ATT&CK context remains separate from base priority and uses defensive wording.
- `attack-navigator-layer.json`: optional Navigator layer containing CTID-backed mapped techniques for the run.
- Coverage-gap Navigator output: optional defensive layer for techniques with partial, missing, or unknown detection coverage.
- `evidence-bundle.zip`: analysis JSON, generated reports, manifest with SHA256 hashes, ATT&CK source provenance, and any Navigator layer generated for the run.
- Manifest entries checksum every generated artifact, including optional ATT&CK Navigator output.

The bundle does not claim ATT&CK coverage for unmapped CVEs. Unmapped findings remain useful evidence because they document that no CTID mapping was available for the selected source.

## Current Acceptance Checks

The current Workbench ATT&CK contract is aligned when:

- CTID JSON is documented as the Workbench canonical source.
- Heuristic, fuzzy, and LLM-generated mappings are explicitly out of scope.
- ATT&CK fields stay separate from base priority fields.
- API, UI, and artifact wording does not imply that ATT&CK changes the base score.
- Evidence artifacts include enough source provenance to reproduce the ATT&CK context for a run.
