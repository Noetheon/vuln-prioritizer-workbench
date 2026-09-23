"""Small evidence-derived fields needed by lists and governance aggregates."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.decision_core.contracts import FindingDecisionEvidenceV2


def decision_read_summary(evidence: FindingDecisionEvidenceV2) -> dict[str, Any]:
    """Extract display fields without serializing provider facts or observations."""
    return read_summary_from_payload(
        {
            "priority_evidence": {"raw": evidence.priority_evidence.raw},
            "governance": {"waiver": evidence.governance.waiver},
            "occurrence_scope": evidence.occurrence_scope.model_dump(mode="json")
            if evidence.occurrence_scope is not None
            else {},
            "remediation": {"sla": evidence.remediation.sla},
        }
    )


def read_summary_from_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Materialize the v2 display contract; also used for bounded schema backfill."""
    raw = _record(_record(payload.get("priority_evidence")).get("raw"))
    governance = _record(payload.get("governance"))
    records = (
        raw,
        payload,
        _record(payload.get("occurrence_scope")),
        _record(raw.get("provenance")),
    )
    waiver: dict[str, Any] = {}
    for source in (governance.get("waiver"), raw.get("waiver"), raw, governance):
        waiver.update(_record(source))
    status = _text(waiver.get("waiver_status")) or _text(waiver.get("status"))
    sla = _record(_record(payload.get("remediation")).get("sla"))
    return {
        "sla": {
            "label": _text(sla.get("label")),
            "target_hours": _integer(sla.get("target_hours")),
            "target_days": _integer(sla.get("target_days")),
        }
        if _text(sla.get("label"))
        else None,
        "owner": _first_text(records, ("owner", "asset_owner", "waiver_owner")),
        "service": _first_text(
            records, ("business_service", "service", "asset_business_service", "waiver_service")
        ),
        "asset": _first_text(records, ("asset_key", "target_ref")),
        "environment": _first_text(records, ("environment", "asset_environment")),
        "waiver_status": status.strip().lower() if status else None,
    }


def _first_text(records: tuple[Mapping[str, Any], ...], keys: tuple[str, ...]) -> str | None:
    return next(
        (value for record in records for key in keys if (value := _text(record.get(key)))), None
    )


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _record(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}
