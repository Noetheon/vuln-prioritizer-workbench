from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

from sqlmodel import Session
from utils.workbench_contracts import _seed_analysis_evidence, _seed_finding_evidence
from utils.workbench_env import (
    DEMO_CVE_LOG4SHELL,
    DEMO_CVE_XZ,
    WorkbenchApiEnv,
    create_analysis_run,
    create_asset,
    create_component,
    create_finding,
    create_project_via_api,
    create_provider_snapshot,
    create_vulnerability,
    local_api_headers,
)

from app.decision_core.contracts import OccurrenceEvidenceV2
from app.models.base import get_datetime_utc

CVE_CREDENTIALS = "CVE-2023-0001"
CVE_SUPPRESSED = "CVE-2023-0002"


def test_risk_insights_returns_trend_top_driver_and_levers(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    ids = _seed_risk_history(workbench_api_env, uuid.UUID(project["id"]))

    response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/risk-insights",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["project_id"] == project["id"]
    assert payload["baseline_open_finding_count"] == 3
    assert payload["baseline_average_risk_score"] == 33.3
    assert payload["baseline_total_risk_score"] == 100.0
    assert payload["risk_target_score"] == 30.0

    trend = payload["trend"]
    assert [point["run_id"] for point in trend] == [
        str(ids["first_run_id"]),
        str(ids["second_run_id"]),
    ]
    first_point, second_point = trend
    assert first_point["average_risk_score"] == 70.0
    assert first_point["max_risk_score"] == 80.0
    assert first_point["open_finding_count"] == 2
    assert first_point["kev_count"] == 1
    assert first_point["counts_by_priority"] == {
        "Critical": 1,
        "High": 1,
        "Medium": 0,
        "Low": 0,
    }
    assert second_point["average_risk_score"] == 33.3
    assert second_point["max_risk_score"] == 50.0
    assert second_point["open_finding_count"] == 3
    assert second_point["kev_count"] == 1
    assert second_point["counts_by_priority"] == {
        "Critical": 1,
        "High": 1,
        "Medium": 0,
        "Low": 1,
    }

    driver = payload["top_driver"]
    assert driver is not None
    assert driver["cve_id"] == DEMO_CVE_LOG4SHELL
    assert driver["risk_score"] == 50.0
    assert driver["in_kev"] is True
    assert driver["priority"] == "Critical"
    assert driver["component_label"] == "log4j-core 2.14.1"
    assert driver["score_reasons"] == ["EPSS and KEV make this urgent."]

    levers = payload["mitigation_levers"]
    assert [lever["kind"] for lever in levers] == [
        "component_upgrade",
        "recommended_action",
    ]
    component_lever, action_lever = levers
    assert payload["recommended_lever_id"] == component_lever["lever_id"]
    assert component_lever["lever_id"].startswith("component_upgrade-")
    assert component_lever["action_label"] == "Upgrade log4j-core 2.14.1 to 2.17.2"
    assert component_lever["component_name"] == "log4j-core"
    assert component_lever["target_version"] == "2.17.2"
    assert component_lever["resolved_finding_count"] == 2
    assert component_lever["resolved_kev_count"] == 1
    assert component_lever["risk_score_sum"] == 80.0
    assert component_lever["risk_score_share_percent"] == 80
    assert component_lever["projected_average_risk_score"] == 20.0
    assert component_lever["average_delta"] == 13.3
    assert component_lever["top_cve_ids"] == [DEMO_CVE_LOG4SHELL, DEMO_CVE_XZ]
    assert component_lever["roadmap_lane"] == "now"
    assert component_lever["nist_csf_function"] == "Protect"
    assert component_lever["attack_tactics"] == ["initial-access"]
    assert component_lever["attack_techniques"] == [
        {
            "technique_id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactics": ["initial-access"],
            "finding_count": 2,
        }
    ]
    assert action_lever["action_label"] == "Rotate exposed credentials."
    assert action_lever["resolved_finding_count"] == 1
    assert action_lever["risk_score_sum"] == 20.0
    assert action_lever["risk_score_share_percent"] == 20
    assert action_lever["projected_average_risk_score"] == 40.0
    assert action_lever["average_delta"] == -6.7
    assert action_lever["roadmap_lane"] == "next"
    assert action_lever["nist_csf_function"] == "Protect"
    assert action_lever["attack_techniques"] == []


def test_risk_insights_empty_project_returns_empty_payload(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/risk-insights",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["baseline_average_risk_score"] is None
    assert payload["baseline_open_finding_count"] == 0
    assert payload["baseline_total_risk_score"] == 0.0
    assert payload["risk_target_score"] == 30.0
    assert payload["recommended_lever_id"] is None
    assert payload["trend"] == []
    assert payload["top_driver"] is None
    assert payload["mitigation_levers"] == []

    invalid_runs = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/risk-insights",
        headers=headers,
        params={"runs": 0},
    )
    assert invalid_runs.status_code == 422


def test_risk_insights_missing_project_returns_404(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    missing_id = uuid.UUID("00000000-0000-4000-8000-000000000404")

    response = workbench_api_env.client.get(
        f"/api/v1/projects/{missing_id}/risk-insights",
        headers=headers,
    )

    assert response.status_code == 404


def _seed_risk_history(
    env: WorkbenchApiEnv,
    project_id: uuid.UUID,
) -> dict[str, uuid.UUID]:
    """Seed two scan runs with per-run decision evidence plus noise runs."""
    app_models = env.app_models
    repositories = env.repositories
    with Session(env.engine) as session:
        asset = create_asset(session, app_models, repositories, project_id=project_id)
        component = create_component(session, repositories)
        log4shell = create_vulnerability(session, repositories, cve_id=DEMO_CVE_LOG4SHELL)
        xz = create_vulnerability(
            session,
            repositories,
            cve_id=DEMO_CVE_XZ,
            cvss_score=8.8,
            severity="HIGH",
        )
        credentials = create_vulnerability(
            session,
            repositories,
            cve_id=CVE_CREDENTIALS,
            cvss_score=6.5,
            severity="MEDIUM",
        )
        suppressed = create_vulnerability(
            session,
            repositories,
            cve_id=CVE_SUPPRESSED,
            cvss_score=9.1,
            severity="CRITICAL",
        )
        component_critical = create_finding(
            session,
            app_models,
            repositories,
            project_id=project_id,
            vulnerability_id=log4shell.id,
            component_id=component.id,
            asset_id=asset.id,
            cve_id=DEMO_CVE_LOG4SHELL,
        )
        component_high = create_finding(
            session,
            app_models,
            repositories,
            project_id=project_id,
            vulnerability_id=xz.id,
            component_id=component.id,
            asset_id=asset.id,
            cve_id=DEMO_CVE_XZ,
        )
        action_low = create_finding(
            session,
            app_models,
            repositories,
            project_id=project_id,
            vulnerability_id=credentials.id,
            asset_id=asset.id,
            cve_id=CVE_CREDENTIALS,
        )
        vex_suppressed = create_finding(
            session,
            app_models,
            repositories,
            project_id=project_id,
            vulnerability_id=suppressed.id,
            asset_id=asset.id,
            cve_id=CVE_SUPPRESSED,
        )
        snapshot = create_provider_snapshot(session, repositories)
        evidence_repo = repositories.EvidenceRepository(session)

        first_run = create_analysis_run(
            session,
            app_models,
            repositories,
            project_id=project_id,
            provider_snapshot_id=snapshot.id,
            filename="scan-1.json",
        )
        first_items = [
            _finding_evidence(
                app_models,
                finding=component_critical,
                run=first_run,
                project_id=project_id,
                asset=asset,
                component=component,
                priority=app_models.FindingPriority.CRITICAL,
                priority_rank=1,
                risk_score=80.0,
                operational_rank=1,
                in_kev=True,
            ),
            _finding_evidence(
                app_models,
                finding=component_high,
                run=first_run,
                project_id=project_id,
                asset=asset,
                component=component,
                priority=app_models.FindingPriority.HIGH,
                priority_rank=2,
                risk_score=60.0,
                operational_rank=2,
            ),
        ]
        first_records = _persist_run_evidence(
            evidence_repo,
            project_id=project_id,
            snapshot_id=snapshot.id,
            run=first_run,
            items=first_items,
        )
        # Backdate the first run so run ordering and "latest evidence" lookups
        # are deterministic even when both runs are seeded within the same tick.
        backdated = get_datetime_utc() - timedelta(hours=2)
        first_run.started_at = backdated
        session.add(first_run)
        for record in first_records:
            record.created_at = backdated
            session.add(record)

        second_run = create_analysis_run(
            session,
            app_models,
            repositories,
            project_id=project_id,
            provider_snapshot_id=snapshot.id,
            filename="scan-2.json",
        )
        fix_occurrence = OccurrenceEvidenceV2(
            analysis_run_id=str(second_run.id),
            fix_version="2.17.2",
        )
        second_items = [
            _finding_evidence(
                app_models,
                finding=component_critical,
                run=second_run,
                project_id=project_id,
                asset=asset,
                component=component,
                priority=app_models.FindingPriority.CRITICAL,
                priority_rank=1,
                risk_score=50.0,
                operational_rank=1,
                in_kev=True,
            ).model_copy(update={"occurrences": [fix_occurrence]}),
            _finding_evidence(
                app_models,
                finding=component_high,
                run=second_run,
                project_id=project_id,
                asset=asset,
                component=component,
                priority=app_models.FindingPriority.HIGH,
                priority_rank=2,
                risk_score=30.0,
                operational_rank=2,
            ).model_copy(update={"occurrences": [fix_occurrence]}),
            _finding_evidence(
                app_models,
                finding=action_low,
                run=second_run,
                project_id=project_id,
                asset=asset,
                component=None,
                priority=app_models.FindingPriority.LOW,
                priority_rank=4,
                risk_score=20.0,
                operational_rank=3,
                action="Rotate exposed credentials.",
            ),
            _finding_evidence(
                app_models,
                finding=vex_suppressed,
                run=second_run,
                project_id=project_id,
                asset=asset,
                component=None,
                priority=app_models.FindingPriority.CRITICAL,
                priority_rank=1,
                risk_score=95.0,
                operational_rank=4,
                in_kev=True,
            ).model_copy(update={"suppressed_by_vex": True}),
        ]
        _persist_run_evidence(
            evidence_repo,
            project_id=project_id,
            snapshot_id=snapshot.id,
            run=second_run,
            items=second_items,
        )
        for finding, cve_id in (
            (component_critical, DEMO_CVE_LOG4SHELL),
            (component_high, DEMO_CVE_XZ),
        ):
            session.add(
                app_models.FindingAttackContext(
                    finding_id=finding.id,
                    analysis_run_id=second_run.id,
                    cve_id=cve_id,
                    mapped=True,
                    source="test-reviewed-attack-context",
                    review_status="reviewed",
                    defensive_note="Reviewed defensive context for roadmap explainability only.",
                    rationale="Seeded reviewed mapping for risk-insights API coverage.",
                    technique_ids_json=["T1190"],
                    tactic_ids_json=["TA0001"],
                    mappings_json=[
                        {
                            "attack_object_id": "T1190",
                            "attack_object_name": "Exploit Public-Facing Application",
                            "confidence": "high",
                            "tactics": ["initial-access"],
                        }
                    ],
                )
            )

        # Noise runs that must not show up in the trend.
        create_analysis_run(
            session,
            app_models,
            repositories,
            project_id=project_id,
            provider_snapshot_id=snapshot.id,
            filename="failed.json",
            status=app_models.AnalysisRunStatus.FAILED,
        )
        create_analysis_run(
            session,
            app_models,
            repositories,
            project_id=project_id,
            provider_snapshot_id=snapshot.id,
            input_type="provider_update",
            filename="provider.json",
        )

        ids = {"first_run_id": first_run.id, "second_run_id": second_run.id}
        session.commit()
        return ids


def _persist_run_evidence(
    evidence_repo: Any,
    *,
    project_id: uuid.UUID,
    snapshot_id: uuid.UUID,
    run: Any,
    items: list[Any],
) -> list[Any]:
    analysis_evidence = evidence_repo.upsert_analysis_evidence(
        project_id=project_id,
        analysis_run_id=run.id,
        provider_snapshot_id=snapshot_id,
        evidence=_seed_analysis_evidence(
            project_id=project_id,
            run=run,
            provider_snapshot_id=snapshot_id,
            provider_snapshot_hash="sha256:risk-insights-snapshot",
            finding_count=len(items),
            counts_by_priority={},
            locked_provider_data=True,
            findings=items,
        ),
    )
    return evidence_repo.replace_finding_decision_evidence(
        analysis_evidence_id=analysis_evidence.id,
        project_id=project_id,
        analysis_run_id=run.id,
        evidence_items=items,
    )


def _finding_evidence(
    app_models: Any,
    *,
    finding: Any,
    run: Any,
    project_id: uuid.UUID,
    asset: Any,
    component: Any,
    priority: Any,
    priority_rank: int,
    risk_score: float,
    operational_rank: int,
    in_kev: bool = False,
    action: str = "Upgrade log4j-core.",
) -> Any:
    _ = app_models
    return _seed_finding_evidence(
        finding=finding,
        analysis_run_id=run.id,
        project_id=project_id,
        asset_key=asset.asset_key,
        asset_name=asset.name or asset.asset_key,
        component_name=component.name if component is not None else "standalone-service",
        component_version=(component.version or "") if component is not None else "",
        priority=priority,
        priority_rank=priority_rank,
        risk_score=risk_score,
        operational_rank=operational_rank,
        epss=0.9442 if in_kev else 0.31,
        cvss=10.0 if in_kev else 7.5,
        in_kev=in_kev,
        rationale="EPSS and KEV make this urgent."
        if in_kev
        else "Provider evidence indicates remediation priority.",
        action=action,
        confidence="high",
        flags=[],
    )
