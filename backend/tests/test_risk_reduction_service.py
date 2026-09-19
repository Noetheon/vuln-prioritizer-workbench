from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

from app.decision_core.readmodels import DecisionFindingView
from app.models import AnalysisRun
from app.models.enums import AnalysisRunStatus, FindingStatus
from app.services.risk_reduction import build_project_risk_reduction_payload, risk_index_history


def test_risk_history_includes_successful_native_evaluations() -> None:
    now = datetime(2026, 9, 6, tzinfo=UTC)
    native = AnalysisRun(
        project_id=uuid.uuid4(),
        input_type="reevaluation",
        status=AnalysisRunStatus.COMPLETED,
        risk_index=42,
        finished_at=now,
    )
    points = risk_index_history([native])
    assert len(points) == 1
    assert points[0].run_id == native.id
    assert points[0].risk_index == 42


def test_risk_reduction_sums_actionable_findings_and_residual_steps() -> None:
    payload = build_project_risk_reduction_payload(
        [
            _view(
                "CVE-2021-44228",
                risk_score=99.0,
                component_name="log4j-core",
                service="payments",
                asset_key="payments-api",
                owner="payments-team",
                action="Upgrade log4j-core to a fixed version.",
                in_kev=True,
                epss=0.95,
                cvss=10.0,
            ),
            _view(
                "CVE-2022-22965",
                risk_score=88.0,
                component_name="spring-core",
                service="identity",
                asset_key="identity-api",
                owner="identity-team",
                action="Deploy Spring fixed release.",
                priority="High",
                epss=0.23,
                cvss=8.1,
            ),
        ]
    )

    assert payload.current_actionable_risk == 187.0
    assert payload.actionable_finding_count == 2
    assert payload.largest_driver is not None
    assert payload.largest_driver.dimension == "service"
    assert payload.largest_driver.label == "payments"
    assert [step.model_dump() for step in payload.residual_steps] == [
        {
            "label": "Current",
            "risk_score": 187.0,
            "reduction": 0.0,
            "actionable_finding_count": 2,
            "risk_index": 93.5,
        },
        {
            "label": "After top 1",
            "risk_score": 88.0,
            "reduction": 99.0,
            "actionable_finding_count": 1,
            "risk_index": 88.0,
        },
        {
            "label": "After top 3",
            "risk_score": 0.0,
            "reduction": 187.0,
            "actionable_finding_count": 0,
            "risk_index": 0.0,
        },
        {
            "label": "Remaining",
            "risk_score": 0.0,
            "reduction": 187.0,
            "actionable_finding_count": 0,
            "risk_index": 0.0,
        },
    ]


def test_risk_reduction_excludes_fixed_suppressed_and_tracks_governance_debt() -> None:
    payload = build_project_risk_reduction_payload(
        [
            _view("CVE-2024-0001", risk_score=40.0),
            _view("CVE-2024-0002", risk_score=90.0, status=FindingStatus.FIXED.value),
            _view("CVE-2024-0003", risk_score=80.0, suppressed_by_vex=True),
            _view("CVE-2024-0004", risk_score=70.0, status=FindingStatus.ACCEPTED.value),
            _view("CVE-2024-0005", risk_score=60.0, waived=True),
        ]
    )

    assert payload.current_actionable_risk == 40.0
    assert payload.actionable_finding_count == 1
    assert payload.governance_debt_risk == 130.0
    assert [item.cve_id for item in payload.top_opportunities] == ["CVE-2024-0001"]


def test_risk_reduction_groups_by_cve_component_and_action() -> None:
    payload = build_project_risk_reduction_payload(
        [
            _view(
                "CVE-2024-1234",
                risk_score=50.0,
                component_name="openssl",
                component_version="3.0.0",
                action="Upgrade OpenSSL.",
                asset_key="api-a",
            ),
            _view(
                "CVE-2024-1234",
                risk_score=30.0,
                component_name="openssl",
                component_version="3.0.0",
                action="Upgrade OpenSSL.",
                asset_key="api-b",
            ),
            _view(
                "CVE-2024-1234",
                risk_score=20.0,
                component_name="openssl",
                component_version="1.1.1",
                action="Upgrade OpenSSL.",
                asset_key="api-c",
            ),
        ]
    )

    assert [item.expected_reduction for item in payload.top_opportunities] == [80.0, 20.0]
    assert payload.top_opportunities[0].finding_count == 2
    assert payload.top_opportunities[0].affected_assets == ["api-a", "api-b"]


def test_risk_reduction_sorts_equal_reductions_by_threat_signals() -> None:
    payload = build_project_risk_reduction_payload(
        [
            _view("CVE-2024-0002", risk_score=50.0, epss=0.9, cvss=9.8),
            _view("CVE-2024-0001", risk_score=50.0, in_kev=True, epss=0.1, cvss=5.0),
        ]
    )

    assert [item.cve_id for item in payload.top_opportunities] == [
        "CVE-2024-0001",
        "CVE-2024-0002",
    ]


def test_projected_risk_index_matches_actual_remaining_finding_average() -> None:
    findings = [
        _view("CVE-2024-0001", risk_score=100),
        _view("CVE-2024-0002", risk_score=50),
    ]
    before = build_project_risk_reduction_payload(findings)
    after = build_project_risk_reduction_payload(findings[1:])
    assert before.current_risk_index == 75
    assert before.residual_steps[1].risk_index == after.current_risk_index == 50
    assert before.top_opportunities[0].finding_ids == [findings[0].finding.id]


def test_risk_opportunities_preserve_distinct_canonical_components() -> None:
    findings = [
        _view(
            "CVE-2024-0001",
            risk_score=70,
            component_name="shared",
            component_purl="pkg:npm/shared@1.0",
        ),
        _view(
            "CVE-2024-0001",
            risk_score=60,
            component_name="shared",
            component_purl="pkg:pypi/shared@1.0",
        ),
    ]
    opportunities = build_project_risk_reduction_payload(findings).top_opportunities
    assert len(opportunities) == 2
    assert opportunities[0].component_identity != opportunities[1].component_identity
    assert opportunities[0].finding_ids == [findings[0].finding.id]
    assert opportunities[1].finding_ids == [findings[1].finding.id]


def _view(
    cve_id: str,
    *,
    risk_score: float,
    status: str = FindingStatus.OPEN.value,
    priority: str = "Critical",
    component_name: str = "component",
    component_version: str = "",
    component_purl: str | None = None,
    asset_key: str = "asset",
    asset_name: str | None = None,
    service: str = "service",
    owner: str = "owner",
    action: str = "Review and remediate.",
    epss: float | None = None,
    cvss: float | None = None,
    in_kev: bool = False,
    waived: bool = False,
    suppressed_by_vex: bool = False,
) -> DecisionFindingView:
    component = SimpleNamespace(
        name=component_name,
        version=component_version,
        purl=component_purl,
    )
    asset = SimpleNamespace(
        asset_key=asset_key,
        name=asset_name,
        target_ref=None,
        business_service=service,
        owner=owner,
    )
    finding = SimpleNamespace(
        id=uuid.uuid4(),
        cve_id=cve_id,
        dedup_key=f"{cve_id}:{component_name}:{asset_key}",
        status=FindingStatus.OPEN,
        component=component,
        asset=asset,
    )
    evidence = SimpleNamespace(
        cve_id=cve_id,
        dedup_key=f"{cve_id}:{component_name}:{asset_key}",
        status=status,
        priority=priority,
        priority_rank={"Critical": 1, "High": 2, "Medium": 3, "Low": 4}.get(priority, 4),
        risk_score=risk_score,
        operational_rank=1,
        in_kev=in_kev,
        epss=epss,
        cvss_base_score=cvss,
        attack_mapped=False,
        suppressed_by_vex=suppressed_by_vex,
        under_investigation=False,
        waived=waived,
        rationale="Risk rationale.",
        recommended_action=action,
        occurrence_scope=SimpleNamespace(
            component_name=component_name,
            component_version=component_version,
            purl=component_purl,
            package_type=None,
        ),
        occurrences=[],
    )
    return DecisionFindingView(finding=finding, evidence=evidence)
