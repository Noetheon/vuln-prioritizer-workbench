"""Recover real decision history and artifacts, then continue normal work."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from alembic import command
from paths import REPO_ROOT
from utils.decision_scenarios import DecisionScenario
from utils.workbench_env import create_workbench_api_env

from app.core.migration_bootstrap import _alembic_config
from app.services.local_backup import create_backup, database_integrity_ok


def test_restore_preserves_decisions_reports_and_allows_new_evaluation(tmp_path: Path) -> None:
    source = (tmp_path / "source").resolve()
    source.mkdir()
    config = _alembic_config()
    config.set_main_option("sqlalchemy.url", f"sqlite:///{source / 'workbench.db'}")
    command.upgrade(config, "head")
    env, cleanup = create_workbench_api_env(
        database_path=source / "workbench.db", initialize_database=False
    )
    try:
        scenario = DecisionScenario(env, source)
        run = scenario.import_rows(3)
        original_findings = scenario.analysis_report(run["id"])[0]["findings"]
        reports = env.client.get(f"/api/v1/runs/{run['id']}/reports").json()["data"]
        report_bytes = {
            item["download_url"]: env.client.get(item["download_url"]).content for item in reports
        }
        selected = scenario.findings()[0]["id"]
        scenario.evaluate([selected])
        before = {
            item["id"]: scenario.detail(item["id"])["evidence"] for item in scenario.findings()
        }
        revisions = scenario.revision_counts()
        archive = tmp_path / "backup.zip"
        create_backup(source, archive, package_version="contract-test")
        project_id = scenario.project_id
    finally:
        cleanup()
    # Recovery must not accidentally read evidence from the still-existing source.
    source.rename(tmp_path / "source-offline")
    restored = (tmp_path / "restored").resolve()
    result = subprocess.run(
        [sys.executable, "-m", "app.cli", "restore", str(archive), "--data-dir", str(restored)],
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "backend")},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert database_integrity_ok(restored / "workbench.db")
    env, cleanup = create_workbench_api_env(
        database_path=restored / "workbench.db", initialize_database=False
    )
    try:
        scenario = DecisionScenario(env, restored, project_id=project_id)
        assert scenario.revision_counts() == revisions
        assert {
            item["id"]: scenario.detail(item["id"])["evidence"] for item in scenario.findings()
        } == before
        for url, content in report_bytes.items():
            response = env.client.get(url)
            assert response.status_code == 200, response.text
            assert response.content == content
        assert scenario.analysis_report(run["id"])[0]["findings"] == original_findings
        scenario.evaluate([selected])
        assert scenario.revision_counts() == {**revisions, selected: revisions[selected] + 1}
        assert scenario.analysis_report(run["id"])[0]["findings"] == original_findings
    finally:
        cleanup()
