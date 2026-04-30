# ATT&CK/TTP Methodology

This page starts the VPW-055 ATT&CK/TTP methodology for curated local
CVE-to-ATT&CK mappings. It complements the Workbench ATT&CK methodology and
documents the local artifact contract used for reviewable defensive context.

## Scope

Curated mappings are defensive evidence. They may help operators explain
exposure, prioritize review, and check detection coverage. They must not claim
that exploitation happened, and they must not include commands, payloads, or
step-by-step procedure guidance.

The preferred source for CVE-to-ATT&CK mapping remains CTID Mappings Explorer
JSON. Local curated mappings are allowed only when every entry is explicitly
reviewable.

For imported CTID Mappings Explorer JSON, VPW normalizes each mapping to
`source=ctid-mappings-explorer`, `confidence=high`, and
`review_status=reviewed` because the local artifact is an explicit CTID source
snapshot. The `attack validate` quality report still keeps source, confidence,
review status, mapping-type counts, and duplicate-context conflicts visible so a
reviewer can audit what the imported CTID file contributed.

When reviewers need a local-vs-CTID comparison, `attack validate` accepts
`--comparison-mapping-file` with a local curated mapping file while
`--attack-source ctid-json` is selected. The resulting quality report emits
`local_ctid_conflicts[]` instead of merging or overriding either source.

## Tactic, Technique, And Procedure Boundary

ATT&CK content in this project is intentionally limited to defensive context:

| Layer | Meaning in VPW | Allowed report use | Out of scope |
| --- | --- | --- | --- |
| Tactic | The high-level objective category, such as initial access or impact. | Group findings for coverage, ownership, and review sequencing. | Claiming that a real intrusion phase occurred unless KEV or another explicit source says so. |
| Technique | The ATT&CK behavior category, such as `T1190`. | Show source-backed behavior context, technique metadata, and coverage gaps. | Generating CVE-to-technique links from descriptions, keywords, or LLM output. |
| Procedure | A specific implementation detail, command, payload, tool invocation, or step sequence. | Summarize only high-level, sourced defensive context when needed. | Payloads, commands, reproduction steps, exploit chains, or operational guidance. |

Reports may say that a CVE maps to a tactic or technique when that mapping is
present in CTID JSON or a reviewed local artifact. Reports must not say that
the environment was exploited, that a full attack path is confirmed, or that a
procedure is actionable unless a cited source such as CISA KEV or a reviewed
incident source explicitly supports that claim. Even then, VPW keeps the wording
at defensive triage level.

## Required Fields

Every curated mapping object must include:

| Field | Requirement |
| --- | --- |
| `cve_id` | CVE identifier such as `CVE-2021-44228`. `capability_id` may be supplied only as a CTID-compatible alias. |
| `technique_id` | ATT&CK technique or sub-technique ID, matching `T####` or `T####.###`. `attack_object_id` may be supplied only as a CTID-compatible alias. |
| `mapping_type` | One of `exploitation`, `impact`, `post_exploitation`, `mitigation_context`, or `detection_context`. |
| `source` | Human-readable source for the mapping. |
| `confidence` | Enum bucket: `low`, `medium`, or `high`. Numeric confidence values are rejected by the curated artifact validator. |
| `rationale` | Defensive reason for the mapping. |
| `review_status` | One of `unreviewed`, `needs_review`, `reviewed`, `rejected`, or `stale`. |
| `defensive_note` | Required safety note that frames the mapping as defensive context only. |

Optional fields such as `capability_description`, `comments`, and `references`
must remain high-level defensive context. They must not contain exploit payloads,
reproduction steps, credential-testing guidance, or command sequences.

Reviewer rules are enforced by the loader and schema:

- `review_status=reviewed`, `rejected`, or `stale` requires `reviewer` and
  `reviewed_at`.
- `confidence=high` requires `review_status=reviewed`.
- `confidence=low` remains valid but is highlighted in the mapping quality
  report.

## Confidence And Limitations

Confidence describes the mapping evidence, not the likelihood that a local
asset was exploited.

| Confidence | Meaning | Required handling |
| --- | --- | --- |
| `high` | Source-backed mapping reviewed by a named reviewer. | Must have `review_status=reviewed`, `reviewer`, and `reviewed_at`. |
| `medium` | Plausible reviewed defensive context with partial source detail. | Must keep source and rationale visible; should be revisited when better CTID or vendor evidence exists. |
| `low` | Review queue hint or incomplete defensive context. | Must remain visible in quality reports and must not be used as proof of behavior. |

Current limitations:

- ATT&CK context is optional and separate from the CVSS, EPSS, and KEV base
  priority.
- CTID JSON is preferred. Local curated mappings are accepted only with source,
  rationale, confidence, review status, and defensive notes.
- CTID JSON and local curated mappings are explicit alternative sources. They
  are not silently merged; if a local override workflow is added later, it must
  keep local-vs-CTID conflicts visible in evidence.
- Unmapped CVEs stay unmapped. The tool does not fill gaps by guessing from CVE
  text, CWE, vendor names, products, exploit keywords, EPSS rank, or LLM output.
- Free-text source notes can contain upstream vulnerability descriptions. VPW
  authored notes and reports must avoid exploit payloads, commands, reproduction
  steps, and procedure guidance.

## Mapping Review Checklist

Use this checklist for each local curated mapping and for report surfaces that
display ATT&CK context. The GitHub issue template
`.github/ISSUE_TEMPLATE/attack_mapping_review.md` mirrors these checks for
review work.

- Source: CTID JSON or another public defensive source is named, linked where
  possible, and recorded with version/date/checksum when available.
- Provenance: mapping file, technique metadata file, reviewer, and review date
  are captured.
- Tactic/Technique/Procedure: tactic and technique labels are separated from
  procedure-level details; procedure guidance is absent.
- Confidence: confidence is `low`, `medium`, or `high`; high confidence is
  reviewed; stale/rejected/reviewed entries include reviewer metadata.
- Rationale: rationale explains defensive triage, detection, mitigation, or
  management context without claiming local exploitation.
- Safety: comments, notes, report text, and evidence artifacts contain no
  payloads, commands, reproduction steps, weaponization instructions, or active
  probing guidance.
- Unmapped behavior: absent CTID/local mappings remain explicitly unmapped.
- Reporting: reports identify ATT&CK as source-backed defensive context and do
  not claim real exploitation unless KEV or another cited source supports that
  statement.

## Schema And Example

- Schema: [`docs/schemas/attack-curated-mapping.schema.json`](schemas/attack-curated-mapping.schema.json)
- Example: [`docs/examples/example_attack_curated_mapping.json`](examples/example_attack_curated_mapping.json)

The canonical demo file for the duplicate VPW execution track is
`data/cve_attack_mappings.yml`. The schema accepts JSON and YAML-compatible
object shapes after parsing. YAML files should use the same keys as the JSON
example.

## ATT&CK STIX Snapshot Catalog

The Workbench can persist a pinned Enterprise ATT&CK STIX 2.1 bundle as a
versioned local catalog. The catalog stores tactics, techniques, mitigations,
mitigation relationships, `attack_version`, domain, STIX spec version, bundle
SHA256, object counts, and revoked/deprecated state.

This catalog is reference data only. It validates that CTID or curated mapping
technique IDs exist in a known ATT&CK version and exposes the snapshot version
through provider status metadata. It does not create CVE-to-technique mappings
and it does not download live ATT&CK content during CI.

## Validation

Use the published schema for local artifact checks:

```bash
python3 -m pytest -q backend/tests/test_output_schemas.py::test_attack_curated_mapping_example_matches_schema --no-cov
python3 -m vuln_prioritizer.cli attack validate --attack-source local-curated --attack-mapping-file data/cve_attack_mappings.yml --format json
```

The schema and loader reject missing `source`, `rationale`, `confidence`,
reviewer metadata, and malformed ATT&CK technique IDs. Free-text safety still
requires human review; JSON Schema cannot reliably prove that prose contains no
offensive procedure guidance.
