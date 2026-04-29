"""Compatibility facade for ATT&CK enrichment services."""

from __future__ import annotations

from vuln_prioritizer.attack_enrichment import HIGH_IMPACT_TACTICS, AttackEnrichmentService

__all__ = ["AttackEnrichmentService", "HIGH_IMPACT_TACTICS"]
