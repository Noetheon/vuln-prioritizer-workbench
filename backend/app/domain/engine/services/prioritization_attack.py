"""ATT&CK context projection helpers for prioritization."""

from __future__ import annotations

from app.domain.engine.models import AttackConfidence, AttackData, FindingAttackContextSummary


def build_attack_context_summary(
    cve_id: str,
    attack: AttackData,
) -> FindingAttackContextSummary:
    """Build the finding-level ATT&CK context summary for a prioritized finding."""
    confidence = _aggregate_mapping_confidence(attack)
    return FindingAttackContextSummary(
        cve_id=cve_id,
        mapped=attack.mapped,
        source=attack.source,
        source_version=attack.source_version,
        attack_version=attack.attack_version,
        domain=attack.domain,
        attack_relevance=attack.attack_relevance,
        rationale=attack.attack_rationale,
        confidence=confidence,
        low_confidence=confidence == "low",
        techniques=attack.techniques if attack.mapped else [],
        tactics=attack.attack_tactics if attack.mapped else [],
        mappings=attack.mappings if attack.mapped else [],
    )


def _aggregate_mapping_confidence(attack: AttackData) -> AttackConfidence | None:
    labels = [mapping.confidence for mapping in attack.mappings if mapping.confidence is not None]
    if not labels:
        return None
    if "low" in labels:
        return "low"
    if "medium" in labels:
        return "medium"
    return "high"
