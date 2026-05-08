# Workbench ATT&CK Methodology

Current state: this page describes the local Workbench ATT&CK contract reviewed on 2026-04-25. It is not an unshipped milestone plan. It complements the CLI ATT&CK methodology by documenting the implemented API, UI/report, and evidence behavior.

The detailed curated-mapping methodology, Tactic/Technique/Procedure boundary,
confidence rubric, and mapping review checklist live in
[`docs/attack-ttp-methodology.md`](attack-ttp-methodology.md). Workbench report
surfaces follow the same safety contract.

## Source Contract

Workbench ATT&CK context uses CTID Mappings Explorer JSON as the canonical source for CVE-to-ATT&CK mappings.

- CTID JSON is the only canonical source for Workbench CVE-to-ATT&CK mapping decisions.
- Local CSV mapping remains legacy CLI compatibility and is not the Workbench source of record.
- Imported technique metadata enriches names, tactics, URLs, STIX spec/version metadata, and deprecation state; it does not create new CVE mappings.
- Pinned ATT&CK STIX bundles are versioned catalog snapshots for tactics,
  techniques, mitigations, and mitigation relationships. They are not
  CVE-to-technique mapping sources.
- ATT&CK STIX snapshot imports persist `attack_version`, normalized domain,
  STIX spec version, bundle SHA256, object counts, revoked/deprecated state, and
  ProviderSnapshot metadata. Mapping validation can check CTID or curated
  technique IDs against the imported catalog, but it still does not infer new
  mappings.
- CTID-enabled imports record source provenance in run and finding context: source kind, source path, source checksum, ATT&CK version/domain metadata when available, and mapped-CVE counts.
- CVEs absent from the selected CTID source are stored as unmapped. Enabling `ctid-json` without the required mapping file fails import validation instead of falling back to inferred mappings.

## No Generated Mapping

Workbench ATT&CK enrichment is evidence-based and deterministic.

- Do not infer CVE-to-technique links from CVE descriptions, CWE IDs, vendor names, product names, KEV titles, exploit text, or EPSS rank.
- Do not use LLM-generated mappings.
- Do not use fuzzy matching, keyword matching, or tactic guesses to fill CTID gaps.
- Do not silently promote analyst notes into canonical ATT&CK mappings.
- If a CVE is absent from the CTID JSON source, report it as unmapped.
- Curated local mappings require source, confidence, rationale, review status,
  and a defensive note. Free-text comments must stay at defensive triage or
  detection-context level and must not include exploit payloads, commands, or
  step-by-step procedure guidance.
- Curated local mapping confidence is a `low`, `medium`, or `high` enum. High
  confidence requires `review_status=reviewed`; reviewed, rejected, and stale
  entries require `reviewer` and `reviewed_at` metadata.

Analyst annotations are outside the current Workbench contract. If added later, they need separate storage and display from CTID mappings.

## Priority Boundary

ATT&CK is a contextual threat-rank and reporting layer. It is not part of the base priority model.

The base priority remains transparent and rule-based from CVSS, EPSS, and CISA KEV. ATT&CK context can explain exposure paths, likely attacker objectives, dashboard grouping, and management reporting, but it does not silently change `priority`, `priority_rank`, or the published base priority rationale.

The Workbench exposes ATT&CK context separately through fields such as `attack_mapped`, `attack_relevance`, and `threat_context_rank`, plus full finding TTP context. These values are derived from imported CTID mapping type, tactic, technique metadata, and documented local rules. Reports and UI present them as triage context, not as the base remediation priority.

## Current API Surface

The current Workbench API preserves project, import, finding, report, and evidence endpoints while adding ATT&CK context through stable `/api/v1` response fields and report artifacts.

- `POST /api/v1/projects/{project_id}/imports` accepts `attack_source=ctid-json`, `attack_mapping_file`, and `attack_technique_metadata_file` values rooted in the configured ATT&CK artifact directory.
- `GET /api/v1/runs/{run_id}` and `GET /api/v1/runs/{run_id}/summary` include ATT&CK summary fields such as `attack_enabled`, `attack_mapped_cves`, `attack_source`, `attack_version`, `attack_domain`, `attack_mapping_file_sha256`, `attack_technique_metadata_file_sha256`, `attack_metadata_format`, and `attack_stix_spec_version`.
- `GET /api/v1/projects/{project_id}/findings` includes per-finding `attack_mapped` and `threat_context_rank` while keeping base priority fields separate.
- `GET /api/v1/findings/{finding_id}` returns the base finding detail and stored ATT&CK context.
- `GET /api/v1/projects/{project_id}/attack/summary` returns project-level tactic and technique rollups from persisted finding ATT&CK context.
- Report creation supports `POST /api/v1/runs/{run_id}/reports`
  with `format=attack-navigator` and `attack_filter` set to `all`,
  `critical-high`, `kev`, or `no-coverage`. The generated artifact downloads
  through the same checksum-validated report download endpoint as other report
  formats.
- Report and evidence endpoints preserve ATT&CK context in generated artifacts without weakening download path and checksum validation.

## Current UI and Report Surface

The Workbench UI makes ATT&CK useful for triage without presenting it as a hidden score.

- Import flows accept local CTID mapping and technique metadata artifacts when ATT&CK context is enabled.
- Dashboard and findings views surface mapped ATT&CK context separately from the base priority column.
- Finding detail and TTP views show CTID mapping evidence, tactics, techniques, mapping type, source checksum, metadata checksum, and explicit unmapped states.
- "Why this priority?" remains separate from ATT&CK context so users can see that CVSS, EPSS, and KEV still drive the base priority.
- Detection-control and coverage-gap views describe defensive coverage status and recommended defensive follow-up.
- Reports and generated artifacts include ATT&CK context only as optional, provenance-backed context.

## Report Safety Contract

Workbench ATT&CK-Lite report sections must follow these rules:

- Tactics are objective categories, techniques are ATT&CK behavior categories,
  and procedure-level details remain out of scope.
- Report text may present mapped tactics, techniques, mapping types, review
  status, confidence, source, and coverage state.
- Report text must not include payloads, commands, reproduction steps, active
  probing guidance, or operational exploit chains.
- ATT&CK mappings must be described as defensive context, not as proof that a
  local environment was exploited.
- Real-world exploitation claims require KEV or another explicit cited source.
  Without that source, reports may only say that a CVE is mapped to source-backed
  ATT&CK context.
- Unmapped CVEs remain unmapped; report generators must not fill gaps from
  descriptions, keywords, vendor names, or LLM output.

## Current Evidence Artifacts

Evidence artifacts make ATT&CK provenance auditable.

- `analysis.json`: per-finding ATT&CK fields, CTID-backed mappings, source provenance, ATT&CK metadata, and unmapped state.
- Generated Markdown/HTML/JSON/CSV/SARIF reports: ATT&CK context remains separate from base priority and uses defensive wording.
- `attack-navigator-layer.json`: optional Navigator layer containing CTID-backed mapped techniques for the run.
- `governance/detection-coverage.json`: optional evidence-bundle export of operator-supplied detection controls, coverage-gap rollups, and review limitations.
- Workbench evidence bundles include `attack-navigator-layer.json` when the run
  has persisted mapped ATT&CK context. The layer comments findings, KEV status,
  confidence, review status, source, and the current `not assessed` coverage
  placeholder.
- Coverage-gap Navigator output: optional defensive layer for techniques with partial, missing, or unknown detection coverage.
- `evidence-bundle.zip`: analysis JSON, generated reports, manifest with SHA256 hashes, ATT&CK source provenance, and any Navigator layer generated for the run.
- Manifest entries checksum every generated artifact, including optional ATT&CK Navigator output.

The bundle does not claim ATT&CK coverage for unmapped CVEs, and detection coverage is not proof of security or exploitation. Unmapped findings remain useful evidence because they document that no CTID mapping was available for the selected source.

## Current Acceptance Checks

The current Workbench ATT&CK contract is aligned when:

- CTID JSON is documented as the Workbench canonical source.
- Heuristic, fuzzy, and LLM-generated mappings are explicitly out of scope.
- ATT&CK fields stay separate from base priority fields.
- API, UI, and artifact wording does not imply that ATT&CK changes the base score.
- Evidence artifacts include enough source provenance to reproduce the ATT&CK context for a run.
- Reports pass the ATT&CK safety wording checks for demo mappings, snapshot
  reports, and Workbench summary artifacts.
