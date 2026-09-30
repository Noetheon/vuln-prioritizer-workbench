from __future__ import annotations

from pathlib import Path
from typing import Any

from utils.import_contracts import completed_run_payload, configure_upload_dir
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers


def _import(
    env: WorkbenchApiEnv, project_id: str, headers: dict[str, str], cves: list[str]
) -> None:
    response = env.client.post(
        f"/api/v1/projects/{project_id}/imports",
        headers=headers,
        data={"input_type": "cve-list", "resolve_missing": "false"},
        files={"file": ("cves.txt", ("\n".join(cves) + "\n").encode(), "text/plain")},
    )
    completed_run_payload(env, response, headers=headers)


def _dashboard(env: WorkbenchApiEnv, project_id: str, headers: dict[str, str]) -> dict[str, Any]:
    response = env.client.get(f"/api/v1/projects/{project_id}/dashboard", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def test_open_risk_rises_with_new_findings_and_falls_with_closures(
    workbench_api_env: WorkbenchApiEnv, tmp_path: Path
) -> None:
    env = workbench_api_env
    configure_upload_dir(env, tmp_path)
    headers = local_api_headers(env.client)
    project = create_project_via_api(env.client, headers)

    _import(env, project["id"], headers, ["CVE-2021-44228"])
    first = _dashboard(env, project["id"], headers)
    kpis = first["kpis"]
    assert kpis["metric"] == "open-risk-kpis.v1"
    assert first["risk_reduction"]["metric"] == "open-risk-sum.v2"
    assert kpis["open_findings"] == 1
    assert kpis["open_kev"] == 1
    assert kpis["open_critical"] == 1
    assert kpis["open_by_priority"] == {"critical": 1}
    assert kpis["open_risk"] > 0
    assert kpis["open_risk"] == first["risk_reduction"]["current_actionable_risk"]
    assert kpis["closed_findings"] == 0
    assert kpis["mttr_days"] is None
    assert kpis["sla_compliance_rate"] is None
    (point,) = first["risk_reduction"]["history"]
    assert point["open_risk"] == kpis["open_risk"]
    assert point["open_findings"] == 1
    assert point["open_kev"] == 1

    # Adding findings, even lower-scored ones, never shows as less risk.
    _import(env, project["id"], headers, ["CVE-2021-44228", "CVE-2023-4863", "CVE-2019-0708"])
    second = _dashboard(env, project["id"], headers)
    assert second["kpis"]["open_findings"] == 3
    assert second["kpis"]["open_risk"] > kpis["open_risk"]
    history = second["risk_reduction"]["history"]
    assert [item["open_findings"] for item in history] == [1, 3]
    assert history[1]["open_risk"] > history[0]["open_risk"]

    findings = env.client.get(f"/api/v1/projects/{project['id']}/findings", headers=headers).json()[
        "data"
    ]
    log4shell = next(item for item in findings if item["cve_id"] == "CVE-2021-44228")
    resolved = env.client.patch(
        f"/api/v1/findings/{log4shell['id']}/status",
        headers=headers,
        json={"status": "resolved", "reason": "Upgraded log4j-core."},
    )
    assert resolved.status_code == 200, resolved.text

    third = _dashboard(env, project["id"], headers)["kpis"]
    assert third["open_findings"] == 2
    assert third["open_kev"] == second["kpis"]["open_kev"] - 1
    assert third["open_risk"] < second["kpis"]["open_risk"]
    assert third["closed_findings"] == 1
    assert third["mttr_days"] is not None and third["mttr_days"] >= 0
    # Closed at once, well inside its SLA window.
    assert third["closed_with_sla"] == 1
    assert third["sla_compliance_rate"] == 1.0


def test_empty_project_has_zero_kpis(workbench_api_env: WorkbenchApiEnv) -> None:
    env = workbench_api_env
    headers = local_api_headers(env.client)
    project = create_project_via_api(env.client, headers)

    kpis = _dashboard(env, project["id"], headers)["kpis"]

    assert kpis["open_findings"] == 0
    assert kpis["open_risk"] == 0
    assert kpis["mean_open_score"] == 0
    assert kpis["overdue"] == 0
