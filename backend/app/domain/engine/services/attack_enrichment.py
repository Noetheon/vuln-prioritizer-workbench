"""Re-export facade for ATT&CK enrichment services."""

from __future__ import annotations

from app.domain.engine.attack_enrichment import HIGH_IMPACT_TACTICS, AttackEnrichmentService

__all__ = ["AttackEnrichmentService", "HIGH_IMPACT_TACTICS"]
