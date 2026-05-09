"""ATT&CK Navigator helpers for CLI evidence bundles."""

from __future__ import annotations

from typing import Any


def attack_navigator_layer_from_summary(attack_summary: object) -> dict[str, Any] | None:
    if not isinstance(attack_summary, dict):
        return None
    technique_distribution = attack_summary.get("technique_distribution")
    if not isinstance(technique_distribution, dict) or not technique_distribution:
        return None
    techniques: list[dict[str, Any]] = [
        {
            "techniqueID": technique_id,
            "score": count,
            "comment": f"Observed in {count} mapped CVE(s).",
        }
        for technique_id, count in sorted(
            (
                (str(key), int(value))
                for key, value in technique_distribution.items()
                if str(key).strip() and isinstance(value, int | float) and int(value) > 0
            ),
            key=lambda item: (-item[1], item[0]),
        )
    ]
    if not techniques:
        return None
    max_score = max(int(item["score"]) for item in techniques)
    return {
        "name": "vuln-prioritizer ATT&CK coverage",
        "version": "4.5",
        "domain": "enterprise-attack",
        "description": (
            "Navigator layer generated from approved ATT&CK mappings in the evidence bundle."
        ),
        "gradient": {
            "colors": ["#dfe7fd", "#4c6ef5"],
            "minValue": 0,
            "maxValue": max_score,
        },
        "techniques": techniques,
        "legendItems": [{"label": "Mapped technique", "color": "#4c6ef5"}],
        "showTacticRowBackground": True,
        "selectTechniquesAcrossTactics": True,
    }


__all__ = ["attack_navigator_layer_from_summary"]
