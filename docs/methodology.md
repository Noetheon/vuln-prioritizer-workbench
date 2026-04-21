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

Two local ATT&CK modes exist:

- `local-csv`: legacy compatibility mode for small hand-authored CSV mappings
- `ctid-json`: structured CTID Mappings Explorer JSON plus local ATT&CK technique metadata

The `ctid-json` workflow is the preferred current ATT&CK path.

ATT&CK rules:

- ATT&CK is optional
- ATT&CK uses explicit local files only
- no heuristic CVE-to-ATT&CK mapping is performed
- no LLM-generated ATT&CK mapping is performed
- no live TAXII integration is used in this release

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

- `High`: at least one `exploitation_technique` or `primary_impact`, or tactics in the high-impact set
- `Medium`: only `secondary_impact`, or mapped but incomplete metadata
- `Low`: only `uncategorized`
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

The primary priority score does not change in the stable release line:

- `Critical`: KEV or `(EPSS >= 0.70 and CVSS >= 7.0)`
- `High`: `EPSS >= 0.40` or `CVSS >= 9.0`
- `Medium`: `CVSS >= 7.0` or `EPSS >= 0.10`
- `Low`: everything else

ATT&CK is a contextual signal. It enriches explanation, reporting, and management framing without silently changing the score.

Presentation notes:

- KEV membership is surfaced more aggressively in terminal and HTML views as known exploited urgency
- this does not change `priority_label`, sorting, or the published JSON contract

Asset context and VEX follow the same principle:

- asset context changes explanatory recommendation text, not `priority_label`
- VEX determines visibility/applicability at occurrence level
- `--show-suppressed` exposes otherwise hidden fully-suppressed findings

## Comparison Mode

The `compare` command still uses:

- `CVSS-only`: Critical `>= 9.0`, High `>= 7.0`, Medium `>= 4.0`, Low otherwise
- `Enriched`: the default CVSS/EPSS/KEV model above

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
