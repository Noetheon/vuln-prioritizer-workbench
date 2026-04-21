# Concept

## Goal

`vuln-prioritizer` prioritizes known CVEs for operational vulnerability management. The tool is intentionally small, CLI-first, and explicit about methodology.

## Core Security Idea

The core security idea is layered prioritization:

- NVD provides technical severity and metadata
- FIRST EPSS provides a probability signal for near-term exploitation
- CISA KEV provides a known-exploitation signal
- CTID ATT&CK mappings provide adversary-behavior and impact context where official mappings exist

The broader differentiator in the current release line is that this core model now extends cleanly into scanner-native inputs, provenance, asset context, VEX-aware applicability, and CI-friendly outputs without abandoning a small CLI shape.

## Main Workflows

- `analyze` for prioritized triage output
- `compare` for `CVSS-only` versus enriched reasoning
- `explain` for a single-CVE deep dive
- `data status` for cache and source transparency
- `report html` for static executive reporting from saved analysis JSON
- `attack coverage` for mapped versus unmapped visibility
- `attack navigator-layer` for ATT&CK visualization output

## Target Audience

- vulnerability management teams
- security engineering teams
- blue teams
- management and CISO-adjacent reporting audiences

## Scope Boundaries

Out of scope:

- network scanning
- asset discovery
- ticket automation
- SIEM integration
- live ATT&CK TAXII ingestion
- heuristic CVE-to-ATT&CK inference
