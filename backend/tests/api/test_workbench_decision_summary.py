from pathlib import Path

from utils.import_contracts import completed_run_payload, configure_upload_dir
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers


def test_run_summary_preserves_recorded_guidance_after_current_status_changes(
    workbench_api_env: WorkbenchApiEnv, tmp_path: Path
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    response = client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("guidance.txt", b"CVE-2021-44228\n", "text/plain")},
    )
    run = completed_run_payload(workbench_api_env, response, headers=headers)
    summary_url = f"/api/v1/runs/{run['id']}/summary"
    summary_response = client.get(summary_url, headers=headers)
    assert summary_response.status_code == 200
    summary = summary_response.json()["decision_summary"]
    assert summary["finding_count"] == summary["findings_with_guidance"] == 1
    assert summary["missing_guidance_count"] == 0
    assert summary["shortest_actionable_sla"]["target_hours"] == 24
    decision = summary["top_decisions"][0]
    detail = client.get(f"/api/v1/findings/{decision['finding_id']}", headers=headers).json()
    assert decision["guidance"] == detail["evidence"]["remediation"]["raw"]
    changed = client.patch(
        f"/api/v1/findings/{decision['finding_id']}/status",
        headers=headers,
        json={"status": "in_review"},
    )
    assert changed.status_code == 200
    assert client.get(summary_url, headers=headers).json()["decision_summary"] == summary
