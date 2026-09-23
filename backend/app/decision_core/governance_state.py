"""Compact invalidation state for the evaluated governance inputs."""

from __future__ import annotations

from typing import Any

from app.decision_core.contracts import FindingDecisionEvidenceV2


def governance_sync_state(evidence: FindingDecisionEvidenceV2) -> dict[str, Any] | None:
    """Describe inputs that can invalidate a decision without reading its payload."""
    inputs = evidence.evaluation_input
    if (
        inputs is None
        or evidence.evaluation is None
        or evidence.evaluation.input_sha256 != inputs.fingerprint()
        or any(
            flag.code == "asset_context_rescore_needed"
            for flag in evidence.priority_evidence.data_quality_flags
        )
    ):
        return None
    return {
        "workbench_waiver": inputs.workbench_waiver.model_dump(mode="json")
        if inputs.workbench_waiver is not None
        else None,
        "scope": evidence.governance.waiver.get("waiver_scope")
        if inputs.workbench_waiver is not None
        else None,
        "source_rules": bool(inputs.waiver_rules),
        "evaluation_date": inputs.evaluation_date.isoformat(),
    }
