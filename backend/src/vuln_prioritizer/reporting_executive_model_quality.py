"""Data-quality and mapping-confidence model builders for executive reports."""

from __future__ import annotations

from collections import Counter
from typing import Any

from vuln_prioritizer.reporting_executive_utils import _float_value, _int_value, _pct, _text


def _quality_rows(metadata: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    total = max(len(findings), 1)
    return [
        {
            "label": "Missing CVSS",
            "value": sum(1 for item in findings if _float_value(item.get("cvss_base_score")) < 0),
            "pct": _pct(
                sum(1 for item in findings if _float_value(item.get("cvss_base_score")) < 0),
                total,
            ),
        },
        {
            "label": "Missing EPSS",
            "value": sum(1 for item in findings if _float_value(item.get("epss")) < 0),
            "pct": _pct(sum(1 for item in findings if _float_value(item.get("epss")) < 0), total),
        },
        {
            "label": "Findings without ATT&CK",
            "value": sum(1 for item in findings if not item.get("attack_mapped")),
            "pct": _pct(sum(1 for item in findings if not item.get("attack_mapped")), total),
        },
        {
            "label": "Provider data-quality flags",
            "value": sum(1 for item in findings if item.get("data_quality_flags")),
            "pct": _pct(sum(1 for item in findings if item.get("data_quality_flags")), total),
        },
        {
            "label": "Low data confidence",
            "value": sum(
                1 for item in findings if _text(item.get("data_quality_confidence")) == "low"
            ),
            "pct": _pct(
                sum(1 for item in findings if _text(item.get("data_quality_confidence")) == "low"),
                total,
            ),
        },
        {
            "label": "Suppressed by VEX",
            "value": _int_value(metadata.get("suppressed_by_vex"))
            or sum(1 for item in findings if item.get("suppressed_by_vex")),
            "pct": _pct(
                _int_value(metadata.get("suppressed_by_vex"))
                or sum(1 for item in findings if item.get("suppressed_by_vex")),
                total,
            ),
        },
        {
            "label": "Active waivers",
            "value": _int_value(metadata.get("waived_count"))
            or sum(1 for item in findings if item.get("waived")),
            "pct": _pct(
                _int_value(metadata.get("waived_count"))
                or sum(1 for item in findings if item.get("waived")),
                total,
            ),
        },
        {
            "label": "Input warnings",
            "value": len([item for item in metadata.get("warnings", []) if item]),
            "pct": 100 if metadata.get("warnings") else 0,
        },
    ]


def _mapping_confidence_model(findings: list[dict[str, Any]]) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    for finding in findings:
        mappings = finding.get("attack_mappings")
        if not isinstance(mappings, list):
            continue
        for mapping in mappings:
            if not isinstance(mapping, dict):
                continue
            confidence = _text(mapping.get("confidence"), default="")
            if confidence:
                counts[confidence.title()] += 1
    if not counts:
        return {
            "available": False,
            "total": sum(1 for item in findings if item.get("attack_mapped")),
            "rows": [
                {
                    "label": "Confidence scoring",
                    "count": "not supplied",
                    "detail": "The supplied ATT&CK mappings did not include confidence buckets.",
                }
            ],
        }
    total = sum(counts.values())
    return {
        "available": True,
        "total": total,
        "rows": [
            {
                "label": label,
                "count": count,
                "pct": _pct(count, total),
                "detail": f"{count} reviewed mapping(s)",
            }
            for label, count in counts.most_common()
        ],
    }


__all__ = ["_mapping_confidence_model", "_quality_rows"]
