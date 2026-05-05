# Methodology

## Input

Supported input formats:

- TXT files with one CVE per line
- CSV files with a `cve` or `cve_id` column
- Trivy JSON
- Grype JSON
- CycloneDX JSON
- SPDX JSON
- OWASP Dependency-Check JSON
- documented GitHub alerts JSON export
- Nessus XML export (`.nessus`)
- pinned OpenVAS XML export

Input is normalized, validated, and deduplicated. Invalid lines become warnings instead of aborting the whole run.
For XML ingest, the parser rejects `DOCTYPE` and `ENTITY` declarations before parsing.

## Data Enrichment

### NVD

- one request per CVE via `cveId`
- English description preferred
- CVSS selection order: `v4.0 -> v3.1 -> v3.0 -> v2`
- the chosen CVSS family is stored as `cvss_version`

### EPSS

- batch requests with chunking under the documented query limit
- fields used: `epss`, `percentile`, and response date

### KEV

- default source: official CISA JSON feed
- fallback: official `cisagov/kev-data` mirror
- optional local JSON or CSV file

### ATT&CK

Three local ATT&CK modes exist:

- `local-csv`: legacy compatibility mode for small hand-authored CSV mappings
- `local-curated`: reviewed YAML/JSON curated mappings with confidence enum,
  source, rationale, reviewer metadata, and defensive notes
- `ctid-json`: structured CTID Mappings Explorer JSON plus local ATT&CK technique metadata

The `ctid-json` workflow is the preferred current ATT&CK path.

Detailed ATT&CK methodology, the Tactic/Technique/Procedure boundary, the
confidence rubric, and the mapping review checklist are documented in
[`docs/attack-ttp-methodology.md`](attack-ttp-methodology.md). Workbench-specific
API, UI, report, and evidence behavior is documented in
[`docs/workbench-attack-methodology.md`](workbench-attack-methodology.md).

ATT&CK rules:

- ATT&CK is optional
- ATT&CK uses explicit local files only
- no heuristic CVE-to-ATT&CK mapping is performed
- no LLM-generated ATT&CK mapping is performed
- no live TAXII integration is used in this release
- curated local mappings require source, confidence, rationale, review status,
  and a defensive note; they must not include exploit payloads, commands, or
  step-by-step procedure guidance
- curated local mapping confidence is one of `low`, `medium`, or `high`;
  low-confidence entries are preserved but highlighted in the quality report

## ATT&CK Data Model

When CTID mode is enabled, the tool stores:

- structured mapping objects per CVE
- ATT&CK technique metadata with names, tactics, URLs, and deprecation flags
- `attack_relevance` as a local deterministic helper label derived from the imported ATT&CK context
- `attack_rationale`
- run-level `attack_summary`

Compatibility projections remain available:

- `attack_techniques`
- `attack_tactics`
- `attack_note`

## ATT&CK Relevance

`attack_relevance` is deterministic, local to this tool, and separate from the main priority label. It is not an official CTID field and it does not override the primary `CVSS + EPSS + KEV` priority:

- `High`: at least one `exploitation_technique`, `primary_impact`, `exploitation`, or `impact`, or tactics in the high-impact set
- `Medium`: only `secondary_impact` or `post_exploitation`, or mapped but incomplete metadata
- `Low`: only `uncategorized`, `mitigation_context`, or `detection_context`
- `Unmapped`: no CTID mapping found

High-impact tactics are:

- `initial-access`
- `execution`
- `privilege-escalation`
- `credential-access`
- `lateral-movement`
- `exfiltration`
- `impact`

## Prioritization

The base priority label is deterministic and rule-based:

- `Critical`: KEV or `(EPSS >= 0.70 and CVSS >= 7.0)`
- `High`: `EPSS >= 0.40` or `CVSS >= 9.0`
- `Medium`: `CVSS >= 7.0` or `EPSS >= 0.10`
- `Low`: everything else

The priority enum used by the decision engine is:

- `Critical`
- `High`
- `Medium`
- `Low`
- `Suppressed`
- `Accepted`
- `Fixed`

`priority_label` keeps the base CVSS/EPSS/KEV result. `priority_state` may move
to `Suppressed`, `Accepted`, or `Fixed` when VEX or waiver evidence changes the
operational lifecycle state.

The `operational_score` is a deterministic 0-100 queueing score. It is built
from explicit contributions for base priority, KEV, EPSS/CVSS boundary matches,
asset exposure, production context, asset criticality, and active occurrence
count, then clamped to the 0-100 range. Business service and owner are evaluated
as zero-point routing context so reviewers can see how ownership data affected
the explanation even when it does not add risk points. Every score includes
`operational_score_reasons` so the score is reviewable rather than opaque.
Unknown asset context is represented as neutral unverified context and is not
treated as safe.

Every generated finding also includes a structured `explanation` object. It
turns the matched rules into stable reason codes such as
`priority.kev.known_exploited`, `priority.critical.epss_cvss`, or
`priority.low.default`; each reason carries its data source, signal value,
threshold, and message. Missing provider data and data-quality flags are surfaced
as notes so reviewers can distinguish a low signal from an unavailable signal.
When asset context is present, the explanation includes `asset.context` with
exposure, environment, criticality, service, owner, and mapped asset count. When
an occurrence has no asset context, the explanation includes an
`asset.context_unknown` warning note.

Each prioritized finding also receives `decision_guidance`. This object is a
defensive recommendation generator for management reporting: it selects one of
`Patch`, `Mitigate`, `Monitor`, `Review`, or `Waiver`, assigns a deterministic
SLA from the effective priority or governance state, builds a business-impact
paragraph from KEV, EPSS, CVSS, and asset context, and emits a decision
statement for top findings. Accepted, suppressed, and fixed findings are not
treated as hidden or done; they receive governance-oriented visibility text and
review/verification SLA guidance.

ATT&CK is a contextual signal. It enriches explanation, reporting, and management framing without silently changing the base priority.

Presentation notes:

- KEV membership is surfaced more aggressively in terminal and HTML views as known exploited urgency
- this does not change `priority_label`

Asset context and VEX follow the same principle:

- asset context changes explanatory recommendation text and the operational queue score, not `priority_label`
- remediation guidance now uses explicit package/component evidence when available
- VEX determines visibility/applicability at occurrence level with deterministic ranked matching
- `--show-suppressed` exposes otherwise hidden fully-suppressed findings

## Comparison Mode

The `compare` command still uses:

- `CVSS-only`: Critical `>= 9.0`, High `>= 7.0`, Medium `>= 4.0`, Low otherwise
- `Enriched`: the default CVSS/EPSS/KEV model above

Workbench project comparison exposes the same baseline through
`GET /api/v1/projects/{project_id}/compare/cvss-only`. The comparison reports
counts per priority, up/down/unchanged rows, and top changes with old/new rank
and the reason for the shift.

This view is intentionally a decision-support lens, not an absolute truth. It
shows how the current policy differs from a CVSS-only baseline; remediation
owners still need to validate asset exposure, business criticality, compensating
controls, and applicability.

`compare` now additionally shows ATT&CK context:

- mapped or unmapped state
- `attack_relevance`
- mapped tactic count and technique count in exports

## Explain Mode

`explain` is the most detailed view and includes:

- CVE metadata
- CVSS score, severity, and version
- EPSS and KEV context
- CVSS-only baseline comparison
- ATT&CK mappings and technique details
- mapping types
- tactic context
- ATT&CK rationale and notes

## ATT&CK Utility Commands

The current release line includes:

- `attack validate`
- `attack coverage`
- `attack navigator-layer`

These commands work from local ATT&CK files and do not require NVD/EPSS/KEV.
`attack validate` and `attack coverage` emit ATT&CK mapping and technique metadata SHA256 values so a run can identify the exact CTID/STIX artifacts used.

## Caching

- optional file cache under `.cache/vuln-prioritizer`
- NVD and EPSS are cached per CVE
- the online KEV catalog is cached as an indexed dataset
- ATT&CK local files are read directly from disk
- `data status` exposes cache timestamps, namespace counts, checksums, and local ATT&CK version metadata
- `data update` is the explicit cache refresh path for NVD, EPSS, and KEV
- `data verify` checks namespace integrity, requested-CVE cache coverage, and pinned local file checksums

Important boundary:

- this remains cache transparency, not a full offline mirror of NVD or EPSS
- NVD and EPSS refresh only the requested CVE set
- KEV refreshes the indexed online catalog or an optional pinned local file

## Limitations

- ATT&CK coverage depends on available CTID mappings
- demo regeneration still depends on live upstream responses for NVD, EPSS, and KEV
- ATT&CK context is intentionally not an asset-aware scoring engine
- VEX status is only applied when a statement matches the occurrence CVE plus component/product or target scope; unmatched or ambiguous real-world product identity still needs human review
- CycloneDX VEX does not infer applicability from the BOM root component, services, dependencies, ratings, or advisory metadata; only `affects[].ref` component/PURL scope is considered
- VEX `justification` and `action_statement` text is preserved as evidence, but it is not treated as a controlled enum beyond the normalized status
