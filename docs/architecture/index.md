# Architecture

## Scope

`vuln-prioritizer` is a CLI and local Workbench for prioritizing known CVEs. It is not a scanner, does not discover vulnerabilities on its own, and does not perform heuristic or LLM-generated CVE-to-ATT&CK mapping.

The current runtime architecture keeps one invariant across all supported inputs:

- normalize many source formats into occurrence-level CVE evidence
- deduplicate to a unique CVE set for enrichment and base prioritization
- preserve provenance, asset context, and VEX applicability as explainable context
- render the same finding model into terminal, Markdown, JSON, SARIF, HTML, API, and Workbench web surfaces

## Flow

```mermaid
flowchart LR
  A["CLI command"] --> B["Input normalization"]
  B --> C["Occurrence model"]
  C --> D["Unique CVE set"]
  C --> E["Asset context and VEX"]
  D --> F["NVD, EPSS, KEV enrichment"]
  D --> G["Optional ATT&CK enrichment"]
  E --> H["Provenance aggregation"]
  F --> I["Prioritization service"]
  G --> I
  H --> I
  I --> J["Finding and comparison models"]
  J --> K["Terminal and file reporters"]
  J --> L["Analysis JSON"]
  L --> M["Static HTML renderer"]
```

## Layering

### CLI surface

`backend/src/vuln_prioritizer/cli.py` is the CLI composition root. It assembles the public Typer tree, shared runtime defaults, and cross-command wiring, while private command modules and private support modules hold command handlers and reusable CLI-only helpers.

Current public command groups:

- `analyze`
- `compare`
- `explain`
- `doctor`
- `snapshot create`
- `snapshot diff`
- `rollup`
- `input validate`
- `state`
- `attack validate`
- `attack coverage`
- `attack navigator-layer`
- `data status`
- `data update`
- `data verify`
- `data export-provider-snapshot`
- `db init`
- `report html`
- `report evidence-bundle`
- `report verify-evidence-bundle`
- `web serve`

The command layer owns flag parsing, validation, cache wiring, and output-mode dispatch. The public command tree is part of the CLI surface; the private command/support modules are implementation detail and do not widen the architecture boundary. Parser-specific logic remains below this layer apart from compatibility routing.

### Workbench surface

The Workbench app is an additive FastAPI/Jinja2 layer over the existing core. `db init` loads the Workbench environment settings and initializes the SQLite schema. `web serve` starts the ASGI application with `--host`, `--port`, and optional `--reload`.

Workbench runtime state is controlled by environment variables for database URL, upload directory, report directory, trusted provider snapshot directory, provider cache directory, upload size, NVD API-key environment name, and the local CSRF token. The Docker Compose path uses named volumes for writable runtime state, keeps provider snapshots writable for refresh jobs, and mounts checked-in demo data read-only so startup can seed locked demo snapshots without making fixture data mutable.

The current web/API import path uses the same local input-format matrix as the CLI for single-upload and multi-upload imports: CVE lists, generic occurrence CSV, Trivy JSON, Grype JSON, Dependency-Check JSON, GitHub alerts JSON, CycloneDX JSON, SPDX JSON, Nessus XML, and OpenVAS XML. XML support remains safe local parsing of exported findings only; the Workbench does not scan systems.

The Workbench threat model and readiness checklist are maintained in [workbench-threat-model.md](../workbench-threat-model.md). The current architecture assumes a trusted local operator, SQLite default storage, and no public-internet exposure until authentication and shared-deployment hardening are added.

### Input normalization

`backend/src/vuln_prioritizer/inputs/loader.py` is the canonical input entry point.

The template-aligned Workbench import boundary is documented in
[vpw-013-importer-contract.md](vpw-013-importer-contract.md). It defines the
pure importer protocol, normalized occurrence DTO, registry lookup behavior,
and the rule that parser adapters stay free of FastAPI, database, repository,
and provider dependencies.

Current normalized types:

- `InputOccurrence`: one source occurrence of a CVE, including component, path, target, asset, and VEX fields
- `ParsedInput`: normalized input document with `occurrences`, `unique_cves`, `warnings`, and `source_stats`

Supported input families currently normalize into the same occurrence model:

- line-oriented CVE lists
- scanner JSON
- SBOM JSON
- advisory/export JSON

`backend/src/vuln_prioritizer/parser.py` remains a backward-compatible facade for historical `.txt` and `.csv` CVE-list flows and delegates internally to the loader.

### Provenance, asset context, and VEX

`backend/src/vuln_prioritizer/services/contextualization.py` aggregates occurrence-level data into per-CVE provenance and context.

Important current rules:

- asset context is occurrence-based, keeps `target_kind` exact, and supports deterministic
  `target_ref` exact/glob rules with precedence
- VEX suppression is evaluated at occurrence level with deterministic specificity-based matching
- `suppressed_by_vex` is true only when all known occurrences are suppressed
- `under_investigation` stays visible and is not silently removed

This layer produces:

- `FindingProvenance`
- `ContextPolicyProfile`
- derived context summary and context recommendation text

### Enrichment providers

`backend/src/vuln_prioritizer/services/enrichment.py` and the provider modules fetch external or local enrichment data.

Current data sources:

- NVD for CVSS, description, references, and selected metadata
- FIRST EPSS
- CISA KEV
- optional local ATT&CK mappings from `local-csv` or `ctid-json`

ATT&CK remains optional and file-based. There is no required remote ATT&CK dependency in the current design.

The parser/provider extension SDK is a static local contract. It documents typed parser and provider definitions, fixture expectations, and validation helpers, but it does not load remote code, discover arbitrary Python entry points, or import user-supplied plugin paths.

### Prioritization

`backend/src/vuln_prioritizer/services/prioritization.py` builds the primary finding set.

The base `priority_label` is intentionally rule-based and transparent:

- `Critical`: KEV or high EPSS+CVSS threshold combination
- `High`: high EPSS or high CVSS
- `Medium`: medium EPSS or medium CVSS
- `Low`: everything else

Current architectural boundary:

- `priority_label` is driven by CVSS, EPSS, and KEV
- ATT&CK, asset context, and VEX add context, rationale, or suppression semantics
- ATT&CK and asset context do not silently introduce a separate opaque risk score

### Reporting

`backend/src/vuln_prioritizer/reporter.py` remains the public reporting facade and delegates report-format, JSON/payload, and serialization helpers to private internal reporting modules.

Current output families:

- terminal tables and panels for interactive use
- Markdown reports for human-readable artifacts
- JSON exports for machine consumption
- SARIF for `analyze`
- static HTML rendered from a previously exported analysis JSON payload

The machine boundary is the JSON export, not the terminal or Markdown layout.

## Contract boundaries

### Stable machine-readable boundary

The current machine-facing contract is centered on the JSON exports:

- analysis JSON
- compare JSON
- explain JSON

These payloads embed `metadata.schema_version`, currently `1.0.0`.

### Derived renderers

`report html` does not rerun enrichment. It consumes an existing analysis JSON export and renders a static document from that saved payload. This keeps HTML generation reproducible and decoupled from live provider state.

### Human-facing surfaces

Terminal tables, panels, warning phrasing, and Markdown table layout are intentionally optimized for readability. They are user-visible interfaces, but not machine-stable parsing targets.

## Cache and live data

NVD, EPSS, and KEV remain live/cache-backed data sources.

The shared provider enrichment contract is documented in
[VPW-022 Provider Cache, Status and Snapshots](vpw-022-provider-cache-status-snapshots.md).
The EPSS-specific batch/cache/freshness behavior is documented in
[VPW-023 EPSS Provider Cache](vpw-023-epss-provider-cache.md).
The KEV-specific JSON/CSV normalization, fixture, source-hash, and Workbench
detail behavior is documented in
[VPW-024 KEV Provider Cache](vpw-024-kev-provider-cache.md).
The NVD-specific CVE API, fallback, CVSS parsing, and missing-CVSS
data-quality behavior is documented in
[VPW-025 NVD Provider Fallback](vpw-025-nvd-provider-fallback.md).

The current `data` command tree is intentionally small:

- `data status` inspects namespace counts, timestamps, and local ATT&CK metadata
- `data update` refreshes NVD/EPSS per-CVE cache entries and the cached KEV catalog
- `data verify` inspects cache coverage, namespace checksums, and pinned local file checksums

Important boundary:

- `data update` is cache-oriented, not a full mirror or snapshot framework for upstream feeds
- NVD and EPSS updates are still scoped to the requested CVE set, not to the whole upstream corpus
- ATT&CK remains local-file based and is verified from disk rather than refreshed from a remote feed

For reproducible automation, prefer:

- explicit `--input-format` over auto-detection
- JSON exports with schema validation
- pinned local ATT&CK mapping files when ATT&CK context is required
