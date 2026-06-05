from __future__ import annotations

import uuid

import pytest
from sqlmodel import Session
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers

from app.contracts.decision_evidence import (
    FindingDecisionEvidenceV2,
    PriorityEvidenceV2,
)
from app.services.decision_projection import (
    DecisionEvidenceInvariantError,
    decision_finding_view,
    decision_run_view,
    run_finding_decision_views,
)


def test_decision_finding_view_prefers_evidence_over_stale_columns(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    app_models = workbench_api_env.app_models
    finding = app_models.Finding(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        vulnerability_id=uuid.uuid4(),
        cve_id="CVE-OLD",
        dedup_key="stale-dedup",
        status=app_models.FindingStatus.FIXED,
        priority=app_models.FindingPriority.LOW,
        priority_rank=99,
        risk_score=1.0,
        operational_rank=99,
        in_kev=False,
        epss=0.01,
        cvss_base_score=1.0,
        recommended_action="Stale action.",
        rationale="Stale rationale.",
    )
    evidence = FindingDecisionEvidenceV2(
        finding_id=str(finding.id),
        analysis_run_id=str(uuid.uuid4()),
        project_id=str(finding.project_id),
        cve_id="CVE-2026-0001",
        dedup_key="evidence-dedup",
        status="open",
        priority="critical",
        priority_rank=1,
        risk_score=98.0,
        operational_rank=1,
        in_kev=True,
        epss=0.91,
        cvss_base_score=9.8,
        rationale="Evidence rationale.",
        recommended_action="Evidence action.",
        priority_evidence=PriorityEvidenceV2(
            priority_label="Critical",
            priority_rank=1,
        ),
    )

    view = decision_finding_view(finding, evidence=evidence)

    assert view.cve_id == "CVE-2026-0001"
    assert view.priority == app_models.FindingPriority.CRITICAL
    assert view.status == app_models.FindingStatus.OPEN
    assert view.risk_score == 98.0
    assert view.in_kev is True
    assert view.recommended_action == "Evidence action."


def test_successful_v2_run_without_analysis_evidence_raises_invariant(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    app_models = workbench_api_env.app_models
    repositories = workbench_api_env.repositories
    with Session(workbench_api_env.engine) as session:
        run = repositories.RunRepository(session).create_analysis_run(
            project_id=uuid.UUID(project["id"]),
            input_type="cve-list",
            filename="missing-evidence.txt",
            status=app_models.AnalysisRunStatus.SUCCEEDED,
        )
        workflow = repositories.WorkflowRepository(session).create_workflow_run(
            kind=app_models.WorkflowRunKind.IMPORT,
            title="Import cve-list",
            handler="test.handler",
            project_id=run.project_id,
            analysis_run_id=run.id,
        )
        repositories.WorkflowRepository(session).finish_workflow(
            workflow.id,
            status=app_models.WorkflowRunStatus.SUCCEEDED,
            stage="succeeded",
            message="Done.",
            result_ref_json={
                "schema_version": "workflow-result-ref.v2",
                "analysis_evidence_id": str(uuid.uuid4()),
                "artifact_refs": [],
            },
        )
        session.commit()

        with pytest.raises(DecisionEvidenceInvariantError):
            decision_run_view(run, session=session)


def test_failed_run_keeps_failure_upload_metadata_without_decision_evidence(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    app_models = workbench_api_env.app_models
    repositories = workbench_api_env.repositories
    with Session(workbench_api_env.engine) as session:
        run = repositories.RunRepository(session).create_analysis_run(
            project_id=uuid.UUID(project["id"]),
            input_type="cve-list",
            filename="bad.txt",
            status=app_models.AnalysisRunStatus.FAILED,
        )
        workflow = repositories.WorkflowRepository(session).create_workflow_run(
            kind=app_models.WorkflowRunKind.IMPORT,
            title="Import cve-list",
            handler="test.handler",
            project_id=run.project_id,
            analysis_run_id=run.id,
        )
        repositories.WorkflowRepository(session).finish_workflow(
            workflow.id,
            status=app_models.WorkflowRunStatus.FAILED,
            stage="parse_upload",
            message="Import failed.",
            result_ref_json={
                "input_upload": {
                    "input_type": "cve-list",
                    "sha256": "sha256:failed-upload",
                }
            },
            diagnostics_json={"stage": "parse_upload", "message": "Import parsing failed."},
        )
        session.commit()

        view = decision_run_view(run, session=session)

    assert view.evidence is None
    assert view.uploads.input == {
        "input_type": "cve-list",
        "sha256": "sha256:failed-upload",
    }
    assert view.counts.created_findings == 0


def test_successful_run_finding_views_require_finding_evidence(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    app_models = workbench_api_env.app_models
    run = app_models.AnalysisRun(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        input_type="cve-list",
        status=app_models.AnalysisRunStatus.SUCCEEDED,
    )
    finding = app_models.Finding(
        id=uuid.uuid4(),
        project_id=run.project_id,
        vulnerability_id=uuid.uuid4(),
        cve_id="CVE-2026-0002",
        priority=app_models.FindingPriority.HIGH,
        priority_rank=2,
    )
    with Session(workbench_api_env.engine) as session:
        with pytest.raises(DecisionEvidenceInvariantError):
            run_finding_decision_views(session, run=run, findings=[finding])
