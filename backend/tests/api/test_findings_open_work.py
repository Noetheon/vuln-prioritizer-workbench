from __future__ import annotations

from pathlib import Path
from typing import Any

from utils.import_contracts import completed_run_payload, configure_upload_dir
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers


def _project_with_one_resolved(
    env: WorkbenchApiEnv, tmp_path: Path
) -> tuple[dict[str, Any], dict[str, str]]:
    configure_upload_dir(env, tmp_path)
    headers = local_api_headers(env.client)
    project = create_project_via_api(env.client, headers)
    response = env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list", "resolve_missing": "false"},
        files={
            "file": (
                "cves.txt",
                b"CVE-2021-44228\nCVE-2023-4863\nCVE-2019-0708\n",
                "text/plain",
            )
        },
    )
    completed_run_payload(env, response, headers=headers)
    findings = _list(env, project["id"], headers, "")["data"]
    log4shell = next(item for item in findings if item["cve_id"] == "CVE-2021-44228")
    resolved = env.client.patch(
        f"/api/v1/findings/{log4shell['id']}/status",
        headers=headers,
        json={"status": "resolved", "reason": "Upgraded log4j-core."},
    )
    assert resolved.status_code == 200, resolved.text
    return project, headers


def _list(
    env: WorkbenchApiEnv, project_id: str, headers: dict[str, str], query: str
) -> dict[str, Any]:
    response = env.client.get(f"/api/v1/projects/{project_id}/findings/?{query}", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def test_open_work_filter_splits_the_queue(
    workbench_api_env: WorkbenchApiEnv, tmp_path: Path
) -> None:
    env = workbench_api_env
    project, headers = _project_with_one_resolved(env, tmp_path)

    everything = _list(env, project["id"], headers, "")
    open_work = _list(env, project["id"], headers, "open_work=true")
    closed = _list(env, project["id"], headers, "open_work=false")

    assert everything["count"] == 3
    assert everything["summary"] is None
    assert open_work["count"] == 2
    assert {item["status"] for item in open_work["data"]} == {"open"}
    assert [item["cve_id"] for item in closed["data"]] == ["CVE-2021-44228"]


def test_summary_counts_every_page_of_the_filtered_list(
    workbench_api_env: WorkbenchApiEnv, tmp_path: Path
) -> None:
    env = workbench_api_env
    project, headers = _project_with_one_resolved(env, tmp_path)

    page = _list(env, project["id"], headers, "limit=1&include_summary=true")
    assert len(page["data"]) == 1
    summary = page["summary"]
    assert sum(summary["by_priority"].values()) == page["count"] == 3
    assert summary["open_work"] == 2
    assert summary["kev"] >= 1
    assert summary["overdue"] == 0

    open_work = _list(env, project["id"], headers, "open_work=true&include_summary=true")
    assert sum(open_work["summary"]["by_priority"].values()) == 2
    assert open_work["summary"]["open_work"] == 2
    # Log4Shell is the resolved KEV finding; the open KEV count drops with it.
    assert open_work["summary"]["kev"] == summary["kev"] - 1
