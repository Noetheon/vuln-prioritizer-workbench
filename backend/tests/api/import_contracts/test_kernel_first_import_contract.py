from __future__ import annotations

import json
import uuid
from pathlib import Path

from sqlmodel import Session
from utils.import_contracts import (
    completed_run_payload,
    configure_upload_dir,
)
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
)

from app.decision_core.contracts import FINDING_DECISION_EVIDENCE_SCHEMA_VERSION
from app.models import AnalysisRun, Project, WorkflowRunKind
from app.repositories import WorkflowRepository
from app.services.report_exports import render_analysis_result_json
from app.services.report_service_payload import build_report_payload


def test_kernel_first_import_uses_evidence_as_report_and_workflow_truth(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("kernel-first.txt", b"CVE-2021-44228\nCVE-2024-3094\n", "text/plain")},
    )
    run_payload = completed_run_payload(workbench_api_env, response, headers=headers)
    evidence = run_payload["evidence"]
    assert evidence["analysis_evidence_id"]
    assert evidence["analysis_service"]["kernel"] == "app.decision_core.decision_graph"

    with Session(workbench_api_env.engine) as session:
        run = session.get(AnalysisRun, uuid.UUID(str(run_payload["id"])))
        project_row = session.get(Project, uuid.UUID(project["id"]))
        assert run is not None
        assert project_row is not None
        workflow = WorkflowRepository(session).get_latest_analysis_workflow(
            analysis_run_id=run.id,
            kind=WorkflowRunKind.IMPORT,
        )
        assert workflow is not None
        assert workflow.result_ref_json == {
            "schema_version": "workflow-result-ref.v2",
            "analysis_evidence_id": evidence["analysis_evidence_id"],
            "artifact_refs": [],
        }

        report_payload, _findings, _generated_at = build_report_payload(
            session,
            run=run,
            project=project_row,
        )
        analysis = json.loads(render_analysis_result_json(report_payload))

    assert (
        analysis["analysis_run"]["summary"]["created_findings"]
        == evidence["counts"]["created_findings"]
    )
    assert (
        analysis["analysis_run"]["summary"]["finding_count"] == evidence["counts"]["finding_count"]
    )
    exported_findings = {item["cve_id"]: item for item in analysis["findings"]}
    assert set(exported_findings) == {"CVE-2021-44228", "CVE-2024-3094"}
    for item in exported_findings.values():
        assert item["evidence"]["schema_version"] == FINDING_DECISION_EVIDENCE_SCHEMA_VERSION
        assert item["priority_raw"] == item["evidence"]["priority"]
