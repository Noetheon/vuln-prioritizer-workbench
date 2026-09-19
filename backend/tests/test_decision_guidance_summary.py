from __future__ import annotations

import uuid

from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.services.decision_guidance_summary import summarize_decision_guidance


def _evidence(
    *, hours: int = 24, status: str = "open", rank: int = 1, guidance: bool = True
) -> FindingDecisionEvidenceV2:
    return FindingDecisionEvidenceV2.model_validate(
        {
            "finding_id": str(uuid.uuid4()),
            "analysis_run_id": str(uuid.uuid4()),
            "project_id": str(uuid.uuid4()),
            "cve_id": "CVE-2026-1234",
            "dedup_key": str(uuid.uuid4()),
            "status": status,
            "priority": "Critical",
            "priority_rank": 0,
            "operational_rank": rank,
            "priority_evidence": {"priority_label": "Critical", "priority_rank": 0},
            "occurrence_scope": {"component_name": "library", "target_ref": "test-service"},
            "remediation": {
                "raw": {
                    "recommendation": "patch",
                    "recommendation_label": "Patch",
                    "sla": {
                        "priority": "Critical",
                        "label": f"Within {hours} hours",
                        "target_hours": hours,
                        "guidance": "Follow recorded policy.",
                        "source": "test-policy",
                    },
                    "business_impact": {
                        "level": "critical",
                        "text": "Context remains unconfirmed.",
                        "drivers": [],
                    },
                    "decision_statement": "Verify scope and apply the recorded recommendation.",
                    "visibility": "actionable",
                }
                if guidance
                else {}
            },
        }
    )


def test_summary_preserves_recorded_guidance_and_scoped_context() -> None:
    evidence = _evidence(hours=6)
    summary = summarize_decision_guidance([evidence])
    assert summary.finding_count == summary.actionable_finding_count == 1
    assert summary.recommendation_counts == {"Patch": 1}
    assert summary.shortest_actionable_sla is not None
    assert summary.shortest_actionable_sla.target_hours == 6
    assert summary.shortest_actionable_sla.source == "test-policy"
    assert summary.top_decisions[0].target == "test-service"
    assert summary.top_decisions[0].guidance.business_impact.text == "Context remains unconfirmed."


def test_missing_guidance_is_explicit_instead_of_inferred_from_critical_priority() -> None:
    summary = summarize_decision_guidance([_evidence(guidance=False)])
    assert summary.finding_count == summary.missing_guidance_count == 1
    assert summary.findings_with_guidance == 0
    assert summary.shortest_actionable_sla is None
    assert summary.recommendation_counts == {}
    assert summary.top_decisions == []


def test_summary_sla_only_uses_actionable_evidence_and_keeps_leading_three() -> None:
    evidence = [_evidence(hours=1, status="fixed", rank=1)] + [
        _evidence(hours=hours, rank=rank) for rank, hours in [(4, 72), (3, 48), (2, 24), (1, 12)]
    ]
    summary = summarize_decision_guidance(iter(evidence))
    assert summary.finding_count == 5
    assert summary.actionable_finding_count == 4
    assert summary.findings_with_guidance == 5
    assert summary.shortest_actionable_sla is not None
    assert summary.shortest_actionable_sla.target_hours == 12
    assert [item.finding_id for item in summary.top_decisions] == [
        uuid.UUID(item.finding_id) for item in reversed(evidence[2:])
    ]
