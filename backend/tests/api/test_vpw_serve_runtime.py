from __future__ import annotations

import os
import stat
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.cli import _prepare_runtime_environment, _sqlite_uri, _validate_bind
from app.core.config import Settings
from app.core.db import create_db_engine
from app.core.frontend import mount_packaged_frontend
from app.core.migration_bootstrap import _alembic_config
from app.main import create_app
from app.workers.in_process import InProcessWorkflowWorker
from app.workers.workflow_worker import run_worker_loop

PROJECT_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def _restore_process_environment() -> Iterator[None]:
    original = dict(os.environ)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


def test_packaged_frontend_serves_assets_and_spa_without_masking_unknown_api(
    tmp_path: Path,
) -> None:
    frontend = tmp_path / "frontend"
    assets = frontend / "assets"
    assets.mkdir(parents=True)
    (frontend / "index.html").write_text("<main>VPW packaged frontend</main>", encoding="utf-8")
    (frontend / "favicon.svg").write_text("<svg></svg>", encoding="utf-8")
    (assets / "app-123.js").write_text("window.vpw = true", encoding="utf-8")
    app = FastAPI()
    app.state.workbench_settings = Settings(FRONTEND_HOST="")

    assert mount_packaged_frontend(app, frontend_root=frontend) is True

    with TestClient(app) as client:
        assert "VPW packaged frontend" in client.get("/").text
        assert "VPW packaged frontend" in client.get("/projects/local").text
        asset = client.get("/assets/app-123.js")
        assert asset.status_code == 200
        assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"
        missing_api = client.get("/api/v1/does-not-exist")
        assert missing_api.status_code == 404
        assert missing_api.json()["detail"] == "Not Found"


def test_in_process_worker_supervisor_restarts_after_crash_and_stops_cleanly() -> None:
    calls = 0
    second_started = threading.Event()

    def crash_once_then_wait(**kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("synthetic worker crash")
        second_started.set()
        stop_event = kwargs["stop_event"]
        assert isinstance(stop_event, threading.Event)
        stop_event.wait(2)

    engine = create_db_engine(Settings(SQLALCHEMY_DATABASE_URI="sqlite://"))
    worker = InProcessWorkflowWorker(
        engine=engine,
        settings=Settings(SQLALCHEMY_DATABASE_URI="sqlite://"),
        poll_interval_seconds=0.01,
        restart_delay_seconds=0.01,
        runner=crash_once_then_wait,
    )
    try:
        worker.start()
        assert second_started.wait(2)
        assert worker.restart_count == 1
        assert worker.last_error == "RuntimeError: synthetic worker crash"
        assert worker.is_alive is True
    finally:
        worker.stop(timeout_seconds=2)
        engine.dispose()

    assert worker.is_alive is False


def test_worker_loop_stop_event_interrupts_idle_poll_without_blocking() -> None:
    stop_event = threading.Event()
    engine = create_db_engine(Settings(SQLALCHEMY_DATABASE_URI="sqlite://"))
    stop_event.set()
    started = time.monotonic()
    try:
        run_worker_loop(
            engine=engine,
            settings=Settings(SQLALCHEMY_DATABASE_URI="sqlite://"),
            worker_id="stop-event-test",
            poll_interval_seconds=60,
            stop_event=stop_event,
        )
    finally:
        engine.dispose()
    assert time.monotonic() - started < 0.5


def test_file_sqlite_uses_wal_and_allows_reader_during_writer_lock(tmp_path: Path) -> None:
    database_path = tmp_path / "wal.db"
    settings = Settings(SQLALCHEMY_DATABASE_URI=_sqlite_uri(database_path))
    engine = create_db_engine(settings)
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE lock_probe (id INTEGER PRIMARY KEY)"))
        writer = engine.connect()
        reader = engine.connect()
        try:
            writer.exec_driver_sql("BEGIN IMMEDIATE")
            writer.execute(text("INSERT INTO lock_probe (id) VALUES (1)"))
            journal_mode = reader.execute(text("PRAGMA journal_mode")).scalar_one()
            busy_timeout = reader.execute(text("PRAGMA busy_timeout")).scalar_one()
            foreign_keys = reader.execute(text("PRAGMA foreign_keys")).scalar_one()
            visible_rows = reader.execute(text("SELECT COUNT(*) FROM lock_probe")).scalar_one()
        finally:
            writer.rollback()
            writer.close()
            reader.close()
    finally:
        engine.dispose()

    assert journal_mode == "wal"
    assert busy_timeout == 30_000
    assert foreign_keys == 1
    assert visible_rows == 0


def test_vpw_runtime_environment_is_same_origin_and_loopback_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "BACKEND_CORS_ORIGINS",
        "FRONTEND_HOST",
        "IN_PROCESS_WORKER_ENABLED",
        "SQLALCHEMY_DATABASE_URI",
    ):
        monkeypatch.delenv(name, raising=False)

    root = _prepare_runtime_environment(
        data_dir=tmp_path / "vpw-data",
        host="127.0.0.1",
        port=8765,
        in_process_worker=True,
    )

    assert root.is_dir()
    assert _sqlite_uri(root / "workbench.db") == os.environ["SQLALCHEMY_DATABASE_URI"]
    assert os.environ["FRONTEND_HOST"] == ""
    assert os.environ["BACKEND_CORS_ORIGINS"] == ""
    assert os.environ["IN_PROCESS_WORKER_ENABLED"] == "true"
    snapshot_dir = root / "provider-snapshots"
    assert os.environ["PROVIDER_SNAPSHOT_DIR"] == str(snapshot_dir)
    assert (snapshot_dir / "demo_provider_snapshot.json").is_file()
    if os.name != "nt":
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        assert stat.S_IMODE(snapshot_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE((snapshot_dir / "demo_provider_snapshot.json").stat().st_mode) == 0o600
    with pytest.raises(SystemExit, match="loopback"):
        _validate_bind(host="0.0.0.0", port=8765, allow_network=False)


def test_in_process_runtime_executes_and_persists_import_across_restart(tmp_path: Path) -> None:
    database_url = _sqlite_uri(tmp_path / "runtime.db")
    migration_config = _alembic_config()
    migration_config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(migration_config, "head")
    settings = Settings(
        SQLALCHEMY_DATABASE_URI=database_url,
        FRONTEND_HOST="",
        IN_PROCESS_WORKER_ENABLED=True,
        WORKER_POLL_INTERVAL_SECONDS=0.05,
        IMPORT_UPLOAD_DIR=str(tmp_path / "imports"),
        REPORT_DIR=str(tmp_path / "reports"),
        PROVIDER_CACHE_DIR=str(tmp_path / "cache"),
        PROVIDER_SNAPSHOT_DIR=str(PROJECT_ROOT / "data"),
        ATTACK_ARTIFACT_DIR=str(PROJECT_ROOT / "data" / "attack"),
        DEMO_PROVIDER_SNAPSHOT_ENABLED=True,
    )
    application = create_app(settings)
    with TestClient(application) as client:
        runtime_status = client.get("/api/v1/workbench/status")
        assert runtime_status.status_code == 200
        assert runtime_status.json()["runtime_mode"] == "local-single-process"
        project = client.post("/api/v1/projects/", json={"name": "Restart proof"}).json()
        imported = client.post(
            f"/api/v1/projects/{project['id']}/imports",
            data={
                "input_type": "cve-list",
                "locked_provider_data": "true",
                "provider_snapshot_file": "demo_provider_snapshot.json",
            },
            files={"file": ("cves.txt", b"CVE-2021-44228\n", "text/plain")},
        )
        assert imported.status_code == 200, imported.text
        run_id = imported.json()["id"]
        payload = _wait_for_terminal_run(client, run_id)
        assert payload["status"] == "succeeded"
        assert application.state.in_process_workflow_worker.is_alive is True
    assert application.state.in_process_workflow_worker.is_alive is False

    restarted = create_app(settings)
    with TestClient(restarted) as client:
        persisted = client.get(f"/api/v1/runs/{run_id}")
        assert persisted.status_code == 200
        assert persisted.json()["status"] == "succeeded"
        findings = client.get(f"/api/v1/projects/{project['id']}/findings/")
        assert findings.status_code == 200
        assert findings.json()["count"] == 1


def _wait_for_terminal_run(client: TestClient, run_id: str) -> dict[str, object]:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/runs/{run_id}")
        assert response.status_code == 200, response.text
        payload = response.json()
        if payload["status"] in {"succeeded", "failed", "cancelled"}:
            return payload
        time.sleep(0.05)
    raise AssertionError(f"Run {run_id} did not become terminal.")
