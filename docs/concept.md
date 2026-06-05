# Concept

## Goal

`vuln-prioritizer-workbench` prioritizes known CVEs for operational vulnerability
management. The current product is intentionally small, local-first, and
explicit about methodology, with the FastAPI/React Workbench as the active user
surface.

## Core Security Idea

The core security idea is layered prioritization:

- NVD provides technical severity and metadata
- FIRST EPSS provides a probability signal for near-term exploitation
- CISA KEV provides a known-exploitation signal
- CTID ATT&CK mappings provide adversary-behavior and impact context where official mappings exist

The broader differentiator in the current release line is that this core model
extends into scanner-native inputs, provenance, asset context, VEX-aware
applicability, and reviewer-ready Workbench outputs without becoming a scanner
or enterprise vulnerability-management platform.

## Main Workflows

- create or select a local project
- import existing CVE, scanner, SBOM, VEX, and asset-context evidence
- review the prioritized findings queue and single-finding explanations
- inspect provider freshness, ATT&CK/TTP context, waivers, and asset context
- generate decision reports and evidence bundles

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
