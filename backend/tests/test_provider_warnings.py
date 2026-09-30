from __future__ import annotations

import uuid

from sqlmodel import Session
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers

from app.services.provider_warnings import (
    provider_warning_lines,
    summarize_provider_warnings,
)

PROXY_ERROR = (
    "HTTPSConnectionPool(host='services.nvd.nist.gov', port=443): Max retries exceeded "
    "(Caused by ProxyError('Unable to connect to proxy'))"
)
RAW_WARNINGS = [
    f"NVD lookup failed for CVE-2024-3094: {PROXY_ERROR}",
    f"NVD lookup failed for CVE-2021-44228: {PROXY_ERROR}",
    "Parser note stays as it is.",
    f"EPSS lookup failed for chunk CVE-2024-3094,CVE-2021-44228: {PROXY_ERROR}",
    "KEV catalog load failed: Connection refused",
]
SUMMARIZED = [
    "NVD could not be reached for 2 CVEs, so their CVSS scores and descriptions are missing.",
    "EPSS could not be reached for 2 CVEs, so their priorities were computed without EPSS.",
    "The KEV catalog could not be loaded, so KEV status is unknown for this import.",
]


def test_unreachable_providers_read_as_one_line_each() -> None:
    assert summarize_provider_warnings(RAW_WARNINGS) == [
        *SUMMARIZED,
        "Parser note stays as it is.",
    ]


def test_rate_limits_other_failures_and_stale_kev_are_named() -> None:
    assert summarize_provider_warnings(
        [
            "NVD lookup failed for CVE-2024-3094: 429 Too Many Requests",
            "EPSS lookup failed for chunk CVE-2024-3094: unexpected payload",
            "KEV catalog load failed; using expired cached catalog: timeout",
        ]
    ) == [
        "NVD rate-limited the lookups for 1 CVE, so its CVSS score and description are missing.",
        "EPSS lookups failed for 1 CVE, so its priority was computed without EPSS.",
        "The KEV catalog could not be refreshed, so an expired cached copy was used.",
    ]
    assert summarize_provider_warnings(["KEV provider failed: boom"]) == [
        "The KEV catalog could not be loaded, so KEV status is unknown for this import."
    ]
    assert summarize_provider_warnings([]) == []


def test_provider_lines_are_found_before_and_after_summarizing() -> None:
    assert provider_warning_lines(RAW_WARNINGS) == SUMMARIZED
    # Runs recorded with summarized warnings give the same lines back.
    assert provider_warning_lines(summarize_provider_warnings(RAW_WARNINGS)) == SUMMARIZED
    assert provider_warning_lines(["Parser note stays as it is."]) == []


def test_run_summary_reads_recorded_provider_failures(workbench_api_env: WorkbenchApiEnv) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    app_models = workbench_api_env.app_models
    repositories = workbench_api_env.repositories
    with Session(workbench_api_env.engine) as session:
        run = repositories.RunRepository(session).create_analysis_run(
            project_id=uuid.UUID(project["id"]),
            input_type="cve-list",
            filename="cves.txt",
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
            stage="analysis",
            message="Import failed.",
            # Recorded before warnings were summarized: one raw line per CVE.
            diagnostics_json={"stage": "analysis", "warnings": RAW_WARNINGS},
        )
        session.commit()
        run_id = run.id

    response = workbench_api_env.client.get(f"/api/v1/runs/{run_id}/summary", headers=headers)

    assert response.status_code == 200, response.text
    summary = response.json()
    assert summary["provider_warnings"] == SUMMARIZED
    assert summary["warnings"] == [*SUMMARIZED, "Parser note stays as it is."]
