"""SLA due dates: first seen plus the recorded SLA target, for open work only."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from utils.demo_imports import configure_demo_imports, import_demo_rows
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api

from app.decision_core.sla_due import first_seen_bounds, sla_due, sla_target_hours
from app.models import FindingSlaState, FindingStatus
from app.workers.workflow_worker import run_worker_once

IMPORTED_AT = datetime(2026, 9, 1, tzinfo=UTC)
LOG4SHELL = "CVE-2021-44228"  # KEV: Critical, 24 hours
SYSTEMD = "CVE-2023-26604"  # CVSS 7.8: Medium, 30 days
CURL = "CVE-2023-38546"  # CVSS 3.7: Low, 90 days


def _at(hours: float) -> str:
    return (IMPORTED_AT + timedelta(hours=hours)).isoformat()


def _advance(env: WorkbenchApiEnv, monkeypatch: pytest.MonkeyPatch, hours: float) -> None:
    """Move the clock and let the worker apply the daily governance refresh."""
    monkeypatch.setenv("WORKBENCH_FIXED_NOW", _at(hours))
    run_worker_once(
        engine=env.engine,
        settings=env.client.app.state.workbench_settings,
        worker_id="sla-due-test",
        retry_delay_seconds=0,
    )


def _page(env: WorkbenchApiEnv, project_id: str, query: str = "") -> dict[str, dict]:
    response = env.client.get(f"/api/v1/projects/{project_id}/findings/?limit=100{query}")
    assert response.status_code == 200, response.text
    return {item["cve_id"]: item for item in response.json()["data"]}


def test_due_dates_follow_the_recorded_sla_and_filter_open_work(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = workbench_api_env
    configure_demo_imports(env, tmp_path)
    monkeypatch.setenv("WORKBENCH_FIXED_NOW", _at(0))
    project_id = create_project_via_api(env.client, {}, name="SLA")["id"]
    import_demo_rows(
        env,
        project_id,
        [
            f"{LOG4SHELL},web-1,log4j-core,2.14.1\n".encode(),
            f"{SYSTEMD},web-1,systemd,246\n".encode(),
            f"{CURL},web-1,curl,8.3.0\n".encode(),
        ],
    )

    findings = _page(env, project_id)
    assert {cve: item["sla"]["target_hours"] for cve, item in findings.items()} == {
        LOG4SHELL: 24,
        SYSTEMD: 720,
        CURL: 2160,
    }
    for item in findings.values():
        first_seen = datetime.fromisoformat(item["first_seen_at"]).replace(tzinfo=UTC)
        due_at = datetime.fromisoformat(item["sla_due_at"])
        assert due_at == first_seen + timedelta(hours=item["sla"]["target_hours"])
        assert item["sla_state"] == "on_track"

    _advance(env, monkeypatch, 20)
    assert _page(env, project_id)[LOG4SHELL]["sla_state"] == "due_soon"
    assert set(_page(env, project_id, "&sla=due_soon")) == {LOG4SHELL}
    assert set(_page(env, project_id, "&sla=on_track")) == {SYSTEMD, CURL}

    _advance(env, monkeypatch, 24 * 23)
    assert set(_page(env, project_id, "&sla=overdue")) == {LOG4SHELL}
    assert set(_page(env, project_id, "&sla=due_soon")) == {SYSTEMD}
    assert set(_page(env, project_id, "&sla=on_track")) == {CURL}

    critical = findings[LOG4SHELL]
    closed = env.client.patch(
        f"/api/v1/findings/{critical['id']}/status",
        json={"status": "resolved", "reason": "Patched to 2.17.1."},
    )
    assert closed.status_code == 200, closed.text
    resolved = _page(env, project_id)[LOG4SHELL]
    assert resolved["sla_due_at"] is None
    assert resolved["sla_state"] is None
    assert _page(env, project_id, "&sla=overdue") == {}

    invalid = env.client.get(f"/api/v1/projects/{project_id}/findings/?sla=late")
    assert invalid.status_code == 422


def test_sla_due_matches_query_bounds_at_every_boundary() -> None:
    first_seen = datetime(2026, 9, 1, 12, tzinfo=UTC)
    sla = {"label": "High", "target_hours": 168}
    for offset in (0, 125.9, 126, 126.1, 167.9, 168, 168.1, 400):
        now = first_seen + timedelta(hours=offset)
        due = sla_due(first_seen_at=first_seen, sla=sla, status="open", now=now)
        assert due is not None
        assert due.due_at == first_seen + timedelta(hours=168)
        lower, upper = first_seen_bounds(due.state, hours=168, now=now)
        assert lower is None or first_seen > lower
        assert upper is None or first_seen <= upper
        expected = (
            FindingSlaState.OVERDUE
            if offset >= 168
            else FindingSlaState.DUE_SOON
            if offset >= 126
            else FindingSlaState.ON_TRACK
        )
        assert due.state == expected


def test_sla_due_skips_governed_closed_and_untargeted_findings() -> None:
    now = datetime(2026, 9, 1, tzinfo=UTC)
    naive_first_seen = datetime(2026, 8, 1)
    sla = {"label": "Standard", "target_days": 30}
    assert sla_target_hours(sla) == 720
    assert sla_target_hours({"label": "Emergency", "target_hours": 24, "target_days": 1}) == 24
    assert sla_target_hours({"label": "Governance Review"}) is None
    assert sla_target_hours({"label": "Bad", "target_hours": True}) is None
    assert sla_target_hours(None) is None
    due = sla_due(first_seen_at=naive_first_seen, sla=sla, status="in_review", now=now)
    assert due is not None
    assert due.state == FindingSlaState.OVERDUE
    assert due.due_at == datetime(2026, 8, 31, tzinfo=UTC)
    for status in (
        FindingStatus.RESOLVED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.FIXED,
        FindingStatus.ACCEPTED,
        FindingStatus.SUPPRESSED,
        "unknown",
    ):
        assert sla_due(first_seen_at=naive_first_seen, sla=sla, status=status, now=now) is None
    assert (
        sla_due(
            first_seen_at=naive_first_seen,
            sla={"label": "Governance Review"},
            status="open",
            now=now,
        )
        is None
    )
