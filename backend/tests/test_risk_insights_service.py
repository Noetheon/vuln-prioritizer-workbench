from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import timedelta
from types import SimpleNamespace

from app.models import AnalysisRunStatus
from app.models.base import get_datetime_utc
from app.services.risk_insights import (
    build_mitigation_levers,
    build_risk_trend_points,
    build_top_risk_driver,
    open_decision_views,
)


def test_open_decision_views_filters_resolved_and_vex_suppressed_findings() -> None:
    views = [
        _view("CVE-1", risk_score=90.0),
        _view("CVE-2", risk_score=80.0, status="in_review"),
        _view("CVE-3", risk_score=70.0, status="remediating"),
        _view("CVE-4", risk_score=60.0, status="fixed"),
        _view("CVE-5", risk_score=50.0, status="accepted"),
        _view("CVE-6", risk_score=40.0, suppressed_by_vex=True),
    ]

    open_views = open_decision_views(views)

    assert [view.cve_id for view in open_views] == ["CVE-1", "CVE-2", "CVE-3"]


def test_top_risk_driver_picks_best_operational_rank_with_reasons() -> None:
    runner_up = _view("CVE-LOW", risk_score=99.0, operational_rank=2)
    driver_view = _view(
        "CVE-TOP",
        risk_score=88.0,
        operational_rank=1,
        in_kev=True,
        component=("log4j-core", "2.14.1", "pkg:maven/log4j-core@2.14.1"),
        recommended_action="Upgrade log4j-core.",
        reasons=("KEV listed", "Internet-facing asset"),
    )

    driver = build_top_risk_driver([runner_up, driver_view])

    assert driver is not None
    assert driver.cve_id == "CVE-TOP"
    assert driver.risk_score == 88.0
    assert driver.in_kev is True
    assert driver.priority == "Critical"
    assert driver.component_label == "log4j-core 2.14.1"
    assert driver.recommended_action == "Upgrade log4j-core."
    assert driver.score_reasons == ["KEV listed", "Internet-facing asset"]


def test_top_risk_driver_is_none_without_open_findings() -> None:
    assert build_top_risk_driver([]) is None


def test_mitigation_levers_rank_by_total_risk_and_project_average() -> None:
    component = ("log4j-core", "2.14.1", "pkg:maven/log4j-core@2.14.1")
    cve_a = _view(
        "CVE-A",
        risk_score=90.0,
        in_kev=True,
        component=component,
        fix_versions=("2.17.2",),
    )
    cve_b = _view(
        "CVE-B",
        risk_score=70.0,
        component=component,
        fix_versions=("2.17.2", "2.17.0"),
    )
    cve_c = _view("CVE-C", risk_score=40.0, recommended_action="Rotate credentials")
    views = [
        cve_a,
        cve_b,
        cve_c,
        _view("CVE-D", risk_score=10.0),
    ]
    attack_contexts = [
        _attack_context(
            cve_a.finding_id,
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactics=("initial-access",),
        ),
        _attack_context(
            cve_b.finding_id,
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactics=("initial-access",),
        ),
        _attack_context(
            cve_c.finding_id,
            technique_id="T1110",
            technique_name="Brute Force",
            tactics=("credential-access",),
            review_status="needs_review",
        ),
    ]

    levers = build_mitigation_levers(
        views,
        attack_contexts=attack_contexts,
        baseline_average=52.5,
        baseline_total_risk_score=210.0,
    )

    assert [lever.kind for lever in levers] == [
        "component_upgrade",
        "recommended_action",
        "cve",
    ]

    component_lever = levers[0]
    assert component_lever.lever_id.startswith("component_upgrade-")
    assert component_lever.action_label == "Upgrade log4j-core 2.14.1 to 2.17.2"
    assert component_lever.component_name == "log4j-core"
    assert component_lever.target_version == "2.17.2"
    assert component_lever.resolved_finding_count == 2
    assert component_lever.resolved_kev_count == 1
    assert component_lever.risk_score_sum == 160.0
    assert component_lever.risk_score_share_percent == 76
    assert component_lever.projected_average_risk_score == 25.0
    assert component_lever.average_delta == 27.5
    assert component_lever.top_cve_ids == ["CVE-A", "CVE-B"]
    assert component_lever.roadmap_lane == "now"
    assert component_lever.nist_csf_function == "Protect"
    assert component_lever.attack_tactics == ["initial-access"]
    assert len(component_lever.attack_techniques) == 1
    assert component_lever.attack_techniques[0].technique_id == "T1190"
    assert component_lever.attack_techniques[0].finding_count == 2

    action_lever = levers[1]
    assert action_lever.action_label == "Rotate credentials"
    assert action_lever.risk_score_sum == 40.0
    assert action_lever.nist_csf_function == "Protect"
    assert action_lever.attack_techniques == []
    # Fixing only the mid-score finding raises the remaining average.
    assert action_lever.projected_average_risk_score == 56.7
    assert action_lever.average_delta == -4.2

    cve_lever = levers[2]
    assert cve_lever.action_label == "Remediate CVE-D"
    assert cve_lever.roadmap_lane == "later"
    assert cve_lever.nist_csf_function == "Unclassified"
    assert cve_lever.projected_average_risk_score == 66.7
    assert cve_lever.average_delta == -14.2

    assert (
        len(
            build_mitigation_levers(
                views,
                baseline_average=52.5,
                baseline_total_risk_score=210.0,
                limit=2,
            )
        )
        == 2
    )


def test_mitigation_levers_assign_nist_and_roadmap_lanes_from_evidence() -> None:
    views = [
        _view(
            "CVE-POLICY",
            risk_score=45.0,
            recommended_action="Update incident response policy",
        ),
        _view("CVE-ASSET", risk_score=35.0, recommended_action="Refresh asset inventory"),
        _view("CVE-LOG", risk_score=5.0, recommended_action="Improve monitoring"),
    ]

    levers = build_mitigation_levers(
        views,
        baseline_average=28.3,
        baseline_total_risk_score=85.0,
    )

    by_action = {lever.action_label: lever for lever in levers}
    assert by_action["Update incident response policy"].nist_csf_function == "Govern"
    assert by_action["Refresh asset inventory"].nist_csf_function == "Identify"
    assert by_action["Improve monitoring"].nist_csf_function == "Detect"
    assert by_action["Improve monitoring"].roadmap_lane == "later"


def test_mitigation_lever_resolving_all_open_findings_has_no_projection() -> None:
    views = [_view("CVE-ONLY", risk_score=50.0)]

    levers = build_mitigation_levers(views, baseline_average=50.0)

    assert len(levers) == 1
    assert levers[0].risk_score_sum == 50.0
    assert levers[0].projected_average_risk_score is None
    assert levers[0].average_delta is None


def test_mitigation_levers_without_fix_version_use_generic_upgrade_label() -> None:
    views = [
        _view(
            "CVE-A",
            risk_score=30.0,
            component=("openssl", "1.1.1", None),
        )
    ]

    levers = build_mitigation_levers(views, baseline_average=30.0)

    assert levers[0].action_label == "Upgrade openssl 1.1.1 to a fixed version"
    assert levers[0].target_version is None


def test_mitigation_levers_empty_without_open_findings() -> None:
    assert build_mitigation_levers([], baseline_average=None) == []


def test_risk_trend_points_filter_runs_and_aggregate_open_rows() -> None:
    now = get_datetime_utc()
    run_oldest = _run(AnalysisRunStatus.COMPLETED, started_at=now - timedelta(days=2))
    run_all_resolved = _run(AnalysisRunStatus.COMPLETED, started_at=now - timedelta(days=1))
    run_failed = _run(AnalysisRunStatus.FAILED, started_at=now - timedelta(hours=12))
    run_without_evidence = _run(AnalysisRunStatus.COMPLETED, started_at=now - timedelta(hours=6))
    run_provider_update = _run(
        AnalysisRunStatus.COMPLETED,
        started_at=now - timedelta(hours=3),
        input_type="provider_update",
    )
    run_newest = _run(AnalysisRunStatus.SUCCEEDED, started_at=now)

    rows = [
        _row(run_oldest.id, score=80.0, priority="critical", in_kev=True),
        _row(run_oldest.id, score=61.0, priority="FindingPriority.high"),
        _row(run_oldest.id, score=99.0, status="fixed"),
        _row(run_oldest.id, score=70.0, suppressed=True),
        _row(run_all_resolved.id, score=10.0, status="fixed"),
        _row(run_newest.id, score=20.0, priority="low"),
    ]
    repository = _FakeEvidenceRepository(
        rows,
        evidence_run_ids={
            run_oldest.id,
            run_all_resolved.id,
            run_provider_update.id,
            run_newest.id,
        },
    )

    points = build_risk_trend_points(
        [
            run_newest,
            run_provider_update,
            run_without_evidence,
            run_failed,
            run_all_resolved,
            run_oldest,
        ],
        evidence_repository=repository,
    )

    assert [point.run_id for point in points] == [
        run_oldest.id,
        run_all_resolved.id,
        run_newest.id,
    ]

    oldest_point = points[0]
    assert oldest_point.average_risk_score == 70.5
    assert oldest_point.max_risk_score == 80.0
    assert oldest_point.open_finding_count == 2
    assert oldest_point.kev_count == 1
    assert oldest_point.counts_by_priority == {
        "Critical": 1,
        "High": 1,
        "Medium": 0,
        "Low": 0,
    }

    resolved_point = points[1]
    assert resolved_point.average_risk_score is None
    assert resolved_point.max_risk_score is None
    assert resolved_point.open_finding_count == 0

    newest_point = points[2]
    assert newest_point.average_risk_score == 20.0
    assert newest_point.status is AnalysisRunStatus.SUCCEEDED
    assert newest_point.counts_by_priority["Low"] == 1


class _FakeEvidenceRepository:
    def __init__(
        self,
        rows: list[SimpleNamespace],
        *,
        evidence_run_ids: set[uuid.UUID],
    ) -> None:
        self._rows = rows
        self._evidence_run_ids = evidence_run_ids

    def analysis_evidence_run_ids(
        self,
        analysis_run_ids: Iterable[uuid.UUID],
    ) -> set[uuid.UUID]:
        return {run_id for run_id in analysis_run_ids if run_id in self._evidence_run_ids}

    def finding_decision_evidence_rows_for_runs(
        self,
        analysis_run_ids: Iterable[uuid.UUID],
    ) -> list[SimpleNamespace]:
        wanted = set(analysis_run_ids)
        return [row for row in self._rows if row.analysis_run_id in wanted]


def _run(
    status: AnalysisRunStatus,
    *,
    started_at: object,
    input_type: str = "cve-list",
) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        status=status,
        input_type=input_type,
        filename="scan.json",
        started_at=started_at,
        finished_at=None,
    )


def _row(
    analysis_run_id: uuid.UUID,
    *,
    score: float,
    priority: str = "critical",
    status: str = "open",
    in_kev: bool = False,
    suppressed: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        analysis_run_id=analysis_run_id,
        status=status,
        priority=priority,
        payload_json={
            "risk_score": score,
            "in_kev": in_kev,
            "suppressed_by_vex": suppressed,
        },
    )


def _view(
    cve_id: str,
    *,
    risk_score: float | None,
    status: str = "open",
    suppressed_by_vex: bool = False,
    operational_rank: int = 1,
    priority_rank: int = 1,
    in_kev: bool = False,
    component: tuple[str, str | None, str | None] | None = None,
    recommended_action: str | None = None,
    fix_versions: tuple[str, ...] = (),
    reasons: tuple[str, ...] = (),
) -> SimpleNamespace:
    component_row = None
    component_label = None
    if component is not None:
        name, version, purl = component
        component_row = SimpleNamespace(name=name, version=version, purl=purl)
        component_label = f"{name} {version}" if version else name
    finding = SimpleNamespace(id=uuid.uuid4(), component=component_row, asset=None)
    evidence = SimpleNamespace(
        occurrences=[SimpleNamespace(fix_version=fix, fix_versions=None) for fix in fix_versions],
        priority_evidence=SimpleNamespace(operational_score_reasons=list(reasons)),
    )
    return SimpleNamespace(
        cve_id=cve_id,
        finding=finding,
        finding_id=finding.id,
        status=status,
        suppressed_by_vex=suppressed_by_vex,
        risk_score=risk_score,
        operational_rank=operational_rank,
        priority_rank=priority_rank,
        in_kev=in_kev,
        epss=0.5,
        priority_label="Critical",
        component_label=component_label,
        asset_label=None,
        recommended_action=recommended_action,
        evidence=evidence,
    )


def _attack_context(
    finding_id: uuid.UUID,
    *,
    technique_id: str,
    technique_name: str,
    tactics: tuple[str, ...],
    review_status: str = "reviewed",
) -> SimpleNamespace:
    now = get_datetime_utc()
    return SimpleNamespace(
        finding_id=finding_id,
        mapped=True,
        review_status=review_status,
        created_at=now,
        technique_ids_json=[technique_id],
        tactic_ids_json=list(tactics),
        mappings_json=[
            {
                "attack_object_id": technique_id,
                "attack_object_name": technique_name,
                "confidence": "high",
                "tactics": list(tactics),
            }
        ],
    )
