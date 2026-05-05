# Vuln Prioritizer Workbench - Historical ATT&CK/TTP Masterplan V2

This archived document preserves the intent of an early ATT&CK/TTP expansion
plan. It is historical context only. It is not the active roadmap, acceptance
criteria, deployment guide, or release contract.

Current source-of-truth documents:

- `docs/attack-ttp-methodology.md`
- `docs/workbench-attack-methodology.md`
- `docs/architecture.md`
- `docs/roadmap.md`
- `docs/submission/technical-documentation.md`

## Historical Context

The V2 plan extended the original Workbench masterplan with threat-informed
vulnerability management. It explored how CVE prioritization could include
reviewed MITRE ATT&CK context, detection coverage, compensating controls, and
management narratives without turning the product into an exploitation or
attack-emulation tool.

The plan predates the current active architecture and the later cleanup of the
old second Workbench runtime. Treat implementation details here as historical
unless current documentation repeats them.

## Historical Product Direction

The core product idea was to connect vulnerability prioritization with a
defensive question:

If a known CVE matters in this environment, what attacker behavior could it
enable, what telemetry would help detect related behavior, what compensating
controls may reduce risk, and how should that context be explained to
engineering and management?

The plan emphasized that ATT&CK context should enrich decisions. It should not
silently dominate scoring or imply that every CVE creates a complete attack
chain.

## Historical Safety Boundaries

The archived plan intentionally set strict boundaries:

- No exploit instructions.
- No PoC generation.
- No active probing.
- No offensive automation.
- No automatic CVE-to-ATT&CK inference from vague text.
- No LLM-generated mapping as source of truth.
- No claim that a Navigator layer proves detection coverage.

These boundaries remain aligned with the current product posture.

## Historical Mapping Methodology

The plan proposed that mappings should be explicit, reviewable, and sourced.
Expected mapping metadata included:

- CVE identifier
- ATT&CK tactic and technique
- Mapping source
- Confidence
- Rationale
- Review status
- Safety wording
- ATT&CK version or snapshot context

It also separated mapping types such as official mappings, KEV-related
mappings, curated local mappings, and user-suggested drafts.

Current mapping rules and safety language are documented in
`docs/attack-ttp-methodology.md`.

## Historical Data Source Direction

The plan evaluated defensive sources such as:

- MITRE ATT&CK STIX data
- CTID mappings and related ATT&CK resources
- CISA KEV
- Local curated mappings
- Detection strategy and coverage references

It also emphasized deterministic snapshots so demos, reports, and audit
evidence could be reproduced.

## Historical UI Direction

The early UI ideas included:

- A TTP Context tab on finding details
- ATT&CK tactic and technique summaries
- Detection coverage views
- Navigator layer exports
- Management-ready narrative sections
- Clear labels for unmapped CVEs

The current React frontend and generated API client are the authoritative
browser surfaces.

## Historical API And CLI Direction

The V2 plan sketched API and CLI flows for:

- Validating ATT&CK data
- Loading curated mappings
- Explaining a CVE with mapped context
- Exporting Navigator layers
- Running project-wide TTP summaries

Current API contracts, if present, are defined by the active backend under
`backend/app` and the generated browser client.

## Historical Reporting Direction

The plan proposed report sections that explain:

- Why a finding matters
- Which ATT&CK context is relevant
- Whether detection coverage is known
- Which compensating controls may help
- Which uncertainty remains

This was intended to strengthen evidence and management communication while
preserving the rule-based vulnerability priority model.

## Status

This document is retained only as an English archive synopsis of the original
ATT&CK/TTP planning artifact. It should not be used to override current
architecture, security, release, or product documentation.
