from __future__ import annotations

import json
from pathlib import Path

from vuln_prioritizer.models import (
    FindingDecisionGuidance,
    FindingProvenance,
    InputOccurrence,
    PrioritizedFinding,
    RemediationComponent,
    RemediationPlan,
)
from vuln_prioritizer.services.decision_guidance import DecisionGuidanceService

DOCS_ROOT = Path(__file__).resolve().parents[2] / "docs"


def _finding(
    *,
    cve_id: str = "CVE-2024-0001",
    priority_label: str = "Medium",
    priority_state: str | None = None,
    in_kev: bool = False,
    epss: float | None = 0.2,
    cvss: float | None = 7.5,
    remediation: RemediationPlan | None = None,
    provenance: FindingProvenance | None = None,
    waived: bool = False,
    suppressed_by_vex: bool = False,
    under_investigation: bool = False,
    operational_rank: int = 6,
    data_quality_confidence: str = "high",
) -> PrioritizedFinding:
    return PrioritizedFinding(
        cve_id=cve_id,
        cvss_base_score=cvss,
        epss=epss,
        in_kev=in_kev,
        priority_label=priority_label,
        priority_rank={"Critical": 1, "High": 2, "Medium": 3, "Low": 4}[priority_label],
        priority_state=priority_state or priority_label,
        operational_rank=operational_rank,
        highest_asset_criticality=(
            provenance.highest_asset_criticality if provenance is not None else None
        ),
        provenance=provenance or FindingProvenance(),
        remediation=remediation or RemediationPlan(),
        waived=waived,
        suppressed_by_vex=suppressed_by_vex,
        under_investigation=under_investigation,
        data_quality_confidence=data_quality_confidence,
        rationale="Deterministic test finding.",
        recommended_action="Review remediation options.",
    )


def _fixed_remediation() -> RemediationPlan:
    return RemediationPlan(
        strategy="upgrade",
        components=[
            RemediationComponent(
                name="demo-lib",
                current_version="1.0.0",
                fixed_versions=["1.0.1"],
            )
        ],
        evidence_level="fixed_version",
    )


def _asset_provenance() -> FindingProvenance:
    return FindingProvenance(
        occurrence_count=1,
        active_occurrence_count=1,
        highest_asset_criticality="critical",
        highest_asset_exposure="internet-facing",
        asset_environments=["prod"],
        asset_owners=["platform-team"],
        asset_business_services=["customer-login"],
        occurrences=[
            InputOccurrence(
                cve_id="CVE-2024-0001",
                asset_id="asset-login-prod",
                asset_criticality="critical",
                asset_exposure="internet-facing",
                asset_environment="prod",
                asset_owner="platform-team",
                asset_business_service="customer-login",
            )
        ],
    )


def test_decision_guidance_selects_patch_recommendation_and_emergency_sla_for_critical() -> None:
    finding = _finding(
        priority_label="Critical",
        in_kev=True,
        epss=0.91,
        cvss=9.8,
        remediation=_fixed_remediation(),
        provenance=_asset_provenance(),
        operational_rank=1,
    )

    guidance = DecisionGuidanceService().build(finding)

    assert guidance.recommendation == "patch"
    assert guidance.sla.label == "Emergency"
    assert guidance.sla.target_hours == 24
    assert guidance.business_impact.level == "critical"
    assert "Top finding #1" in guidance.decision_statement
    assert "customer-login" in guidance.business_impact.text


def test_decision_guidance_covers_all_recommendations_and_visibility_states() -> None:
    service = DecisionGuidanceService()

    assert (
        service.build(_finding(priority_label="High", remediation=RemediationPlan())).recommendation
        == "mitigate"
    )
    low_guidance = service.build(_finding(priority_label="Low", epss=0.01, cvss=3.1))
    assert low_guidance.recommendation == "monitor"
    assert service.build(_finding(priority_label="Medium", epss=None)).recommendation == "review"

    accepted = service.build(
        _finding(priority_label="Critical", priority_state="Accepted", waived=True)
    )
    assert accepted.recommendation == "waiver"
    assert accepted.sla.label == "Governance Review"
    assert accepted.business_impact.level == "governance"
    assert "Accepted risk remains visible" in accepted.visibility

    suppressed = service.build(
        _finding(
            priority_label="Critical",
            priority_state="Suppressed",
            suppressed_by_vex=True,
        )
    )
    assert suppressed.recommendation == "monitor"
    assert suppressed.sla.label == "Evidence Review"
    assert suppressed.business_impact.level == "governance"
    assert "Suppressed evidence remains visible" in suppressed.visibility


def test_decision_guidance_uses_evidence_flags_for_governance_sla() -> None:
    service = DecisionGuidanceService()

    accepted = service.build(_finding(priority_label="Critical", waived=True))
    assert accepted.recommendation == "waiver"
    assert accepted.sla.label == "Governance Review"
    assert accepted.business_impact.level == "governance"

    suppressed = service.build(_finding(priority_label="Critical", suppressed_by_vex=True))
    assert suppressed.recommendation == "monitor"
    assert suppressed.sla.label == "Evidence Review"
    assert suppressed.business_impact.level == "governance"


def test_decision_guidance_uses_defensive_wording_without_instructions() -> None:
    guidance = DecisionGuidanceService().build(
        _finding(priority_label="Critical", in_kev=True, remediation=RemediationPlan())
    )
    combined_text = json.dumps(guidance.model_dump(), sort_keys=True).casefold()

    assert guidance.wording_policy == "defensive_no_exploit_steps"
    for forbidden in (
        "proof-of-concept",
        "payload",
        "reverse shell",
        "weaponize",
        "exploit code",
        "run this command",
    ):
        assert forbidden not in combined_text


def test_example_recommendation_decision_matches_model_snapshot() -> None:
    payload = json.loads(
        (DOCS_ROOT / "examples" / "example_recommendation_decision.json").read_text(
            encoding="utf-8"
        )
    )

    guidance = FindingDecisionGuidance.model_validate(payload)
    expected = DecisionGuidanceService().build(
        _finding(
            priority_label="Critical",
            in_kev=True,
            epss=0.91,
            cvss=9.8,
            remediation=_fixed_remediation(),
            provenance=_asset_provenance(),
            operational_rank=1,
        )
    )

    assert guidance.model_dump() == expected.model_dump()
    assert guidance.recommendation == "patch"
    assert guidance.sla.label == "Emergency"
    assert guidance.business_impact.level == "critical"
    assert "Top finding #1" in guidance.decision_statement
