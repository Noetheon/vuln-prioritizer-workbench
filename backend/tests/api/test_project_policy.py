"""Per-project priority thresholds and SLA targets, applied by imports and re-evaluation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from utils.demo_imports import configure_demo_imports, import_demo_rows
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api

from app.workers.workflow_worker import run_worker_once

SYSTEMD = "CVE-2023-26604"  # CVSS 7.8, low EPSS: Medium by default
JACKSON = "CVE-2022-42003"  # CVSS 7.5, low EPSS: Medium by default
DEFAULTS: dict[str, Any] = {
    "critical_epss_threshold": 0.7,
    "critical_cvss_threshold": 7.0,
    "high_epss_threshold": 0.4,
    "high_cvss_threshold": 9.0,
    "medium_epss_threshold": 0.1,
    "medium_cvss_threshold": 7.0,
    "sla_hours": {"critical": 24, "high": 168, "medium": 720, "low": 2160},
}


def _policy_url(project_id: str) -> str:
    return f"/api/v1/projects/{project_id}/policy"


def test_policy_defaults_validation_and_versions(workbench_api_env: WorkbenchApiEnv) -> None:
    client = workbench_api_env.client
    project_id = create_project_via_api(client, {}, name="Policy")["id"]

    initial = client.get(_policy_url(project_id)).json()
    assert initial["is_default"] is True
    assert initial["version"] == 0
    assert {key: initial[key] for key in DEFAULTS} == DEFAULTS
    assert initial["defaults"] == DEFAULTS

    unordered = client.put(_policy_url(project_id), json={**DEFAULTS, "high_epss_threshold": 0.9})
    assert unordered.status_code == 422
    assert "EPSS thresholds must descend" in unordered.json()["detail"]
    slower_critical = client.put(
        _policy_url(project_id),
        json={**DEFAULTS, "sla_hours": {**DEFAULTS["sla_hours"], "critical": 400}},
    )
    assert slower_critical.status_code == 422
    assert "must not decrease" in slower_critical.json()["detail"]

    unchanged = client.put(_policy_url(project_id), json=DEFAULTS).json()
    assert unchanged["changed"] is False
    assert unchanged["evaluation_skipped_reason"] == "The policy did not change."

    stricter = {**DEFAULTS, "high_cvss_threshold": 7.5}
    saved = client.put(_policy_url(project_id), json={**stricter, "reason": "Board decision"})
    assert saved.status_code == 200, saved.text
    body = saved.json()
    assert body["changed"] is True
    assert body["policy"]["version"] == 1
    assert body["policy"]["is_default"] is False
    assert body["policy"]["high_cvss_threshold"] == 7.5
    assert body["evaluation_run_id"] is None
    assert "No existing findings" in body["evaluation_skipped_reason"]
    assert client.put(_policy_url(project_id), json=DEFAULTS).json()["policy"]["version"] == 2
    audit = client.get(f"/api/v1/audit/events?project_id={project_id}").json()["data"]
    assert [event["action"] for event in audit].count("project.policy") == 2


def _worker(env: WorkbenchApiEnv) -> None:
    result = run_worker_once(
        engine=env.engine,
        settings=env.client.app.state.workbench_settings,
        worker_id="project-policy-test",
        retry_delay_seconds=0,
    )
    assert result.completed == 1, result


def _findings(env: WorkbenchApiEnv, project_id: str) -> dict[str, dict]:
    payload = env.client.get(f"/api/v1/projects/{project_id}/findings/?limit=100").json()
    return {item["cve_id"]: item for item in payload["data"]}


def test_policy_changes_reevaluate_priority_and_sla_and_apply_to_new_imports(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = file_backed_workbench_api_env
    configure_demo_imports(env, tmp_path)
    monkeypatch.setenv("WORKBENCH_FIXED_NOW", "2026-09-01T00:00:00+00:00")
    project_id = create_project_via_api(env.client, {}, name="Policy reevaluation")["id"]
    import_demo_rows(env, project_id, [f"{SYSTEMD},web-1,systemd,246\n".encode()])
    before = _findings(env, project_id)[SYSTEMD]
    assert before["priority"] == "medium"
    assert before["sla"]["target_hours"] == 720

    policy = {
        **DEFAULTS,
        "high_cvss_threshold": 7.5,
        "sla_hours": {"critical": 12, "high": 48, "medium": 336, "low": 1440},
    }
    saved = env.client.put(_policy_url(project_id), json=policy).json()
    assert saved["evaluation_run_id"] is not None
    _worker(env)

    after = _findings(env, project_id)[SYSTEMD]
    first_seen = datetime.fromisoformat(after["first_seen_at"]).replace(tzinfo=UTC)
    assert after["priority"] == "high"
    assert after["sla"]["target_hours"] == 48
    assert datetime.fromisoformat(after["sla_due_at"]) == first_seen + timedelta(hours=48)
    detail = env.client.get(f"/api/v1/findings/{after['id']}").json()
    recorded = detail["evidence"]["evaluation_input"]["priority_policy"]
    assert recorded["high_cvss_threshold"] == 7.5
    assert recorded["sla_hours"]["high"] == 48
    assert detail["evidence"]["remediation"]["sla"]["source"] == "project-policy"

    import_demo_rows(
        env,
        project_id,
        [
            f"{SYSTEMD},web-1,systemd,246\n".encode(),
            f"{JACKSON},web-1,jackson-databind,2.13.0\n".encode(),
        ],
    )
    assert _findings(env, project_id)[JACKSON]["priority"] == "high"

    reset = env.client.put(_policy_url(project_id), json=DEFAULTS).json()
    assert reset["policy"]["is_default"] is True
    _worker(env)
    restored = _findings(env, project_id)
    assert restored[SYSTEMD]["priority"] == "medium"
    assert restored[SYSTEMD]["sla"]["target_hours"] == 720
    restored_detail = env.client.get(f"/api/v1/findings/{restored[SYSTEMD]['id']}").json()
    assert "sla_hours" not in restored_detail["evidence"]["evaluation_input"]["priority_policy"]
