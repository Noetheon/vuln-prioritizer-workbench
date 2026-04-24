# Workbench ATT&CK Methodology

This page defines the methodology contract for the Workbench ATT&CK milestones. It complements the CLI ATT&CK methodology by describing how the Workbench should expose ATT&CK context through API, UI, reports, and evidence artifacts.

## Source Contract

Workbench ATT&CK context uses CTID Mappings Explorer JSON as the canonical source for CVE-to-ATT&CK mappings.

- CTID JSON is the only canonical source for Workbench CVE-to-ATT&CK mapping decisions.
- Local CSV mapping remains legacy CLI compatibility and is not the Workbench v0.6 source of record.
- Imported technique metadata may enrich names, tactics, URLs, STIX spec/version metadata, and deprecation state, but it must not create new CVE mappings.
- Pinned ATT&CK STIX bundles are supported as technique metadata snapshots only; they are not CVE-to-technique mapping sources.
- Each Workbench run should record ATT&CK source provenance: source kind, source path or identifier, checksum, import timestamp, and mapping counts.
- Missing CTID data should leave findings unmapped or ATT&CK-unavailable. It must not block base CVE prioritization.

## No Generated Mapping

Workbench ATT&CK enrichment must be evidence-based and deterministic.

- Do not infer CVE-to-technique links from CVE descriptions, CWE IDs, vendor names, product names, KEV titles, exploit text, or EPSS rank.
- Do not use LLM-generated mappings.
- Do not use fuzzy matching, keyword matching, or tactic guesses to fill CTID gaps.
- Do not silently promote analyst notes into canonical ATT&CK mappings.
- If a CVE is absent from the CTID JSON source, report it as unmapped.

Analyst annotations may be supported later, but they must be stored and displayed separately from CTID mappings.

## Priority Boundary

ATT&CK is a contextual threat-rank and reporting layer. It is not part of the base priority model.

The base priority remains transparent and rule-based from CVSS, EPSS, and CISA KEV. ATT&CK context can help explain exposure paths, likely attacker objectives, dashboard grouping, and management reporting, but it must not silently change `priority`, `priority_rank`, or the published base priority rationale.

Workbench may expose a separate deterministic ATT&CK label such as `attack_threat_rank` or `attack_relevance`. That label should be derived only from imported CTID mapping type, tactic, technique metadata, and documented local rules. Reports and UI must make clear that this is context for triage discussions, not the base remediation priority.

## Expected API Surface

The v0.6 Workbench API should preserve existing project, import, finding, report, and evidence endpoints while adding ATT&CK context in stable response fields.

Expected API behavior:

- `POST /api/projects/{project_id}/imports` records the ATT&CK source used for the run when CTID JSON is configured or supplied.
- `GET /api/analysis-runs/{run_id}` and `GET /api/runs/{run_id}/summary` include `attack_summary` with mapped and unmapped counts, top tactics, top techniques, source provenance, and warnings.
- `GET /api/projects/{project_id}/findings` includes ATT&CK summary fields per finding, such as `attack_mapped`, `attack_threat_rank`, tactic count, technique count, and source kind.
- Finding list filters may include `attack_mapped`, `attack_tactic`, `attack_technique`, and `attack_threat_rank`.
- `GET /api/findings/{finding_id}` includes full CTID-backed mappings, mapping types, tactics, techniques, URLs, source checksum, and unmapped state.
- `GET /api/findings/{finding_id}/explain` explains ATT&CK context separately from the base priority rationale.
- `GET /api/providers/status` or an equivalent status endpoint shows CTID availability, checksum, source age, and warnings without treating ATT&CK as a live provider requirement.
- Report and evidence endpoints preserve ATT&CK context in generated artifacts without changing download integrity checks.

If a dedicated Navigator export endpoint is added, it should generate an ATT&CK Navigator layer from CTID-backed mapped techniques only.

## Expected UI Surface

Workbench UI should make ATT&CK useful for triage without making it look like a hidden score.

- Dashboard: show mapped and unmapped counts, top tactics, top techniques, and KEV findings with ATT&CK context.
- Findings table: show concise ATT&CK badges and filters, but keep the base priority column visually distinct.
- Finding detail: show CTID mapping evidence, tactics, techniques, mapping type, technique URL, source checksum, and an explicit unmapped state.
- Explain view: separate "Why this priority?" from "ATT&CK context" so users can see that CVSS, EPSS, and KEV still drive the base priority.
- Provider or settings view: show configured CTID JSON source, last loaded timestamp, checksum, and validation warnings.
- Reports page: offer ATT&CK-aware JSON, Markdown, HTML, evidence bundle, and optional Navigator layer artifacts.

## Expected Evidence Artifacts

Evidence artifacts should make ATT&CK provenance auditable.

- `analysis.json`: per-finding ATT&CK fields, full CTID-backed mappings, source provenance, `attack_summary`, and unmapped state.
- `summary.md` and `executive-report.html`: mapped and unmapped counts, top tactics and techniques, source provenance, warnings, and clear wording that ATT&CK is contextual.
- `attack-navigator-layer.json`: optional Navigator layer containing only CTID-backed mapped techniques.
- `evidence-bundle.zip`: analysis JSON, generated reports, manifest with SHA256 hashes, ATT&CK source provenance, warnings, and any Navigator layer generated for the run.
- Manifest entries: checksum every generated artifact and identify the CTID source checksum used for ATT&CK context.

The bundle must not claim ATT&CK coverage for unmapped CVEs. Unmapped findings remain useful evidence because they document that no CTID mapping was available for the selected source.

## Acceptance Checks

For the v0.6 milestone, documentation and implementation should be reviewed against these checks:

- CTID JSON is documented as the Workbench canonical source.
- Heuristic, fuzzy, and LLM-generated mappings are explicitly out of scope.
- ATT&CK fields are separate from base priority fields.
- API, UI, and artifact wording does not imply that ATT&CK changes the base score.
- Evidence artifacts include enough source provenance to reproduce the ATT&CK context for a run.
