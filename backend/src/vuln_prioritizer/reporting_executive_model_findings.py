"""Executive report finding model builders."""
# ruff: noqa: F401,F403,F405,I001,E501

from __future__ import annotations

from collections import Counter
from typing import Any

from vuln_prioritizer.reporting_executive_constants import (
    PRIORITY_ORDER,
    PRIORITY_TONES,
    SECTION_NAV,
)
from vuln_prioritizer.reporting_executive_utils import (
    _attack_label,
    _attr,
    _baseline_delta_label,
    _basename,
    _dict_value,
    _float_value,
    _format_report_timestamp,
    _int_value,
    _list_first,
    _list_values,
    _pct,
    _positive_int,
    _priority_label,
    _provider_value,
    _report_period,
    _score,
    _sha_preview,
    _short_provider_date,
    _text,
    _truncate,
)

# ruff: noqa: F403,F405

from vuln_prioritizer.reporting_executive_model_helpers import *


def _finding_row(finding: dict[str, Any]) -> dict[str, Any]:
    service = _finding_service(finding)
    asset = _finding_asset(finding)
    if service != "not supplied" and asset != "not supplied":
        asset_service = f"{service} / {asset}"
    elif service != "not supplied":
        asset_service = service
    elif asset != "not supplied":
        asset_service = asset
    else:
        asset_service = "not supplied"
    return {
        "rank": _int_value(finding.get("operational_rank"))
        or _int_value(finding.get("priority_rank")),
        "score": _int_value(finding.get("operational_score")),
        "cve": _text(finding.get("cve_id"), default="CVE"),
        "priority": _priority_label(finding),
        "tone": PRIORITY_TONES.get(_priority_label(finding), "low"),
        "kev": "Yes" if finding.get("in_kev") else "No",
        "epss": _score(finding.get("epss"), digits=3),
        "cvss": _score(finding.get("cvss_base_score"), digits=1),
        "attack": _attack_label(finding),
        "route": _route_label(finding),
        "asset_service": asset_service,
        "owner": _finding_owner(finding),
        "status": _status_label(finding),
        "baseline_delta": _baseline_delta_label(finding),
        "decision_template": _finding_decision_template(finding),
        "sla": _finding_sla_label(finding),
        "action": _finding_decision_statement(finding),
        "rationale": _text(finding.get("rationale"), default="No rationale supplied."),
    }


def _finding_dossier_model(finding: dict[str, Any]) -> dict[str, Any]:
    evidence = _dict_value(finding.get("provider_evidence"))
    nvd = _dict_value(evidence.get("nvd"))
    epss = _dict_value(evidence.get("epss"))
    kev = _dict_value(evidence.get("kev"))
    references = nvd.get("references")
    reference_count = len(references) if isinstance(references, list) else 0
    return {
        "cve": _text(finding.get("cve_id"), default="CVE"),
        "priority": _priority_label(finding),
        "tone": PRIORITY_TONES.get(_priority_label(finding), "low"),
        "cvss": _score(finding.get("cvss_base_score"), digits=1),
        "epss": _score(finding.get("epss"), digits=3),
        "kev": "Yes" if finding.get("in_kev") else "No",
        "route": _route_label(finding),
        "service": _finding_service(finding),
        "owner": _finding_owner(finding),
        "asset": _finding_asset(finding),
        "exposure": _finding_exposure(finding),
        "criticality": _finding_criticality(finding),
        "status": _status_label(finding),
        "vex": _vex_status(finding),
        "baseline_delta": _baseline_delta_label(finding),
        "decision_template": _finding_decision_template(finding),
        "sla": _finding_sla_label(finding),
        "action": _finding_decision_statement(finding),
        "rationale": _text(finding.get("rationale"), default="No rationale supplied."),
        "context_recommendation": _text(
            finding.get("context_recommendation"),
            default="No context-specific recommendation supplied.",
        ),
        "attack": _attack_label(finding),
        "techniques": _list_values(finding.get("attack_techniques")),
        "tactics": _list_values(finding.get("attack_tactics")),
        "provider": [
            {"label": "Published", "value": _text(nvd.get("published"), default="not available")},
            {
                "label": "Last modified",
                "value": _text(nvd.get("last_modified"), default="not available"),
            },
            {"label": "NVD references", "value": str(reference_count)},
            {"label": "Score date", "value": _text(epss.get("date"), default="not available")},
            {"label": "KEV due date", "value": _text(kev.get("due_date"), default="not available")},
            {
                "label": "KEV action",
                "value": _text(kev.get("required_action"), default="not available"),
            },
        ],
    }


__all__ = [
    "_finding_dossier_model",
    "_finding_row",
]
