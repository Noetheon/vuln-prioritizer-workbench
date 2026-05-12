from __future__ import annotations

import sys
import uuid
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session, create_engine, select
from starlette.requests import Request
from utils.workbench_env import (
    WorkbenchApiEnv,
    seed_domain_graph,
)

from app.api.routes import workbench as workbench_route
from app.core import db as db_module
from app.core import rate_limit as rate_limit_module
from app.core import retention as retention_module
from app.core.config import Settings, settings
from app.core.local_actor import configured_local_actor, local_actor_id
from app.models import AuditEvent
from app.repositories.reports import ReportRepository
from app.services.analysis import AnalysisService, WorkbenchAnalysisError
from app.services.import_artifacts import (
    resolve_workbench_attack_artifact_path,
    resolve_workbench_provider_snapshot_path,
    validate_attack_import_options,
)
from app.services.import_errors import ImportServiceError
from vuln_prioritizer.options import AttackSource


def _request(
    path: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    client: tuple[str, int] | None = ("198.51.100.10", 4321),
) -> Request:
    raw_headers = [
        (name.lower().encode("latin-1"), value.encode("latin-1"))
        for name, value in (headers or {}).items()
    ]
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": raw_headers,
            "client": client,
            "server": ("testserver", 80),
        }
    )


def test_local_actor_is_stable_without_db_user_bootstrap(tmp_path: Path) -> None:
    active_settings = replace(
        settings,
        LOCAL_WORKBENCH_USER_EMAIL="Admin@Example.test",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'workbench.db'}",
    )
    engine = db_module.create_db_engine(active_settings)

    assert db_module._connect_args("postgresql+psycopg://workbench@db/workbench") == {}
    assert local_actor_id("ADMIN@example.test") == local_actor_id("admin@example.test")

    actor = configured_local_actor(active_settings)
    assert actor.id == local_actor_id(active_settings.LOCAL_WORKBENCH_USER_EMAIL)
    assert actor.email == active_settings.LOCAL_WORKBENCH_USER_EMAIL
    assert actor.is_active is True

    with Session(engine) as session:
        db_module.init_db(session, active_settings=active_settings)


def test_rate_limit_edges_cover_disabled_limits_and_trusted_forwarding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limiter = rate_limit_module.InMemoryRateLimiter(window_seconds=60)
    monotonic_values = iter([0.0, 10.0, 61.0])
    monkeypatch.setattr(rate_limit_module, "monotonic", lambda: next(monotonic_values))

    assert limiter.check("disabled", limit=0).allowed is True
    assert limiter.check("api:alice", limit=1).allowed is True
    blocked = limiter.check("api:alice", limit=1)
    assert blocked.allowed is False
    assert blocked.retry_after_seconds == 50
    assert limiter.check("api:alice", limit=1).allowed is True
    monkeypatch.setattr(rate_limit_module, "monotonic", lambda: 62.0)
    assert limiter.check("api:preflight", limit=1, record=False).allowed is True
    assert "api:preflight" not in limiter.attempts

    bounded_limiter = rate_limit_module.InMemoryRateLimiter(max_keys=1)
    assert bounded_limiter.check("first", limit=2).allowed is True
    assert bounded_limiter.check("second", limit=2).allowed is True
    assert len(bounded_limiter.attempts) == 1

    disabled_settings = replace(settings, RATE_LIMIT_ENABLED=False)
    assert (
        rate_limit_module.rate_limit_key(_request("/api/v1/projects/"), disabled_settings) is None
    )

    proxy_settings = replace(
        settings,
        API_RATE_LIMIT_PER_MINUTE=7,
        TRUSTED_PROXY_CIDRS=("10.0.0.0/8",),
    )
    forwarded_api = _request(
        "/api/v1/projects/",
        headers={
            "x-forwarded-for": '"[2001:db8::8]:443"',
        },
        client=("10.0.0.8", 1234),
    )
    assert rate_limit_module.rate_limit_key(forwarded_api, proxy_settings) == (
        "api:2001:db8::8",
        7,
    )
    assert rate_limit_module.rate_limit_key(
        _request("/api/v1/projects/", client=("10.0.0.8", 1234)),
        proxy_settings,
    ) == ("api:10.0.0.8", 7)
    assert rate_limit_module.rate_limit_key(_request("/static/index.js"), proxy_settings) is None
    assert rate_limit_module._forwarded_for_host("203.0.113.10:8443") == "203.0.113.10"
    assert rate_limit_module._forwarded_for_host("not-an-ip") is None
    assert (
        rate_limit_module._is_trusted_proxy_host(
            "not-an-ip",
            ("10.0.0.0/8",),
        )
        is False
    )
    assert (
        rate_limit_module._is_trusted_proxy_host(
            "10.0.0.8",
            ("bad-cidr", "10.0.0.0/8"),
        )
        is True
    )


def test_database_rate_limiter_persists_shared_window_state() -> None:
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE rate_limit_bucket ("
                "bucket_key VARCHAR(255) NOT NULL PRIMARY KEY, "
                "request_count INTEGER NOT NULL, "
                "window_started_at DATETIME NOT NULL, "
                "updated_at DATETIME NOT NULL)"
            )
        )
    limiter = rate_limit_module.DatabaseRateLimiter(engine, window_seconds=60)

    assert limiter.check("api:shared", limit=1).allowed is True
    blocked = limiter.check("api:shared", limit=1)
    assert blocked.allowed is False
    assert blocked.retry_after_seconds > 0
    preflight_blocked = limiter.check("api:shared", limit=1, record=False)
    assert preflight_blocked.allowed is False
    assert preflight_blocked.retry_after_seconds > 0
    assert limiter.check("api:preflight", limit=1, record=False).allowed is True

    with engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT COUNT(*) FROM rate_limit_bucket WHERE bucket_key = :key"),
                {"key": "api:preflight"},
            ).scalar_one()
            == 0
        )


def test_user_and_session_admin_routes_are_not_active(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    client = workbench_api_env.client

    password_route = client.post(
        "/api/v1/users/me/password",
        json={
            "current_password": "wrong-password",
            "new_password": "unused-new-password-123",
        },
    )
    activate_route = client.post(f"/api/v1/users/{uuid.uuid4()}/activate")
    deactivate_route = client.post(f"/api/v1/users/{uuid.uuid4()}/deactivate")
    sessions_route = client.get("/api/v1/audit/sessions")

    assert password_route.status_code == 404
    assert activate_route.status_code == 404
    assert deactivate_route.status_code == 404
    assert sessions_route.status_code == 404


def test_workbench_database_readiness_reports_schema_edges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Result:
        def __init__(self, rows: list[tuple[str]] | None = None) -> None:
            self.rows = rows or []

        def one(self) -> tuple[int]:
            return (1,)

        def all(self) -> list[tuple[str]]:
            return self.rows

    class FakeSession:
        def __init__(self, *, versions: list[str] | None = None, fail_select: bool = False) -> None:
            self.versions = versions or []
            self.fail_select = fail_select

        def execute(self, statement: object) -> Result:
            if self.fail_select:
                raise SQLAlchemyError("db unavailable")
            if "alembic_version" in str(statement):
                return Result([(version,) for version in self.versions])
            return Result()

        def get_bind(self) -> object:
            return object()

    class FakeInspector:
        def __init__(self, *, tables: set[str]) -> None:
            self.tables = tables

        def get_table_names(self) -> list[str]:
            return sorted(self.tables)

    required_tables = set(workbench_route.REQUIRED_SCHEMA_TABLES)

    monkeypatch.setattr(
        workbench_route,
        "inspect",
        lambda bind: FakeInspector(tables=required_tables),
    )
    assert workbench_route._database_readiness(FakeSession()) == ("ready", "not_ready")

    monkeypatch.setattr(
        workbench_route,
        "inspect",
        lambda bind: FakeInspector(
            tables=required_tables | {workbench_route.REQUIRED_ALEMBIC_TABLE},
        ),
    )
    assert workbench_route._database_readiness(FakeSession(versions=["old"])) == (
        "ready",
        "not_ready",
    )

    monkeypatch.setattr(
        workbench_route,
        "inspect",
        lambda bind: FakeInspector(
            tables=required_tables | {workbench_route.REQUIRED_ALEMBIC_TABLE},
        ),
    )
    assert workbench_route._database_readiness(
        FakeSession(versions=[workbench_route.ALEMBIC_HEAD])
    ) == ("ready", "ready")
    assert workbench_route._database_readiness(FakeSession(fail_select=True)) == (
        "unavailable",
        "not_ready",
    )


def test_retention_entrypoint_commits_or_rolls_back_by_mode(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    active_settings = replace(
        workbench_api_env.client.app.state.workbench_settings,
        AUDIT_RETENTION_DAYS=30,
    )
    old_timestamp = retention_module.get_datetime_utc() - retention_module.timedelta(days=45)
    with Session(workbench_api_env.engine) as session:
        session.add(
            AuditEvent(
                action="retention.old.dry-run",
                resource_type="test",
                detail_json={},
                created_at=old_timestamp,
            )
        )
        session.add(
            AuditEvent(
                action="retention.old.commit",
                resource_type="test",
                detail_json={},
                created_at=old_timestamp,
            )
        )
        session.commit()

    monkeypatch.setattr(retention_module, "engine", workbench_api_env.engine)
    monkeypatch.setattr(retention_module, "settings", active_settings)
    monkeypatch.setattr(sys, "argv", ["retention", "--dry-run"])
    retention_module.main()
    dry_run_payload = capsys.readouterr().out
    assert '"audit_events": 2' in dry_run_payload
    assert '"dry_run": true' in dry_run_payload

    with Session(workbench_api_env.engine) as session:
        assert session.exec(
            select(AuditEvent).where(AuditEvent.action == "retention.old.dry-run")
        ).first()

    monkeypatch.setattr(sys, "argv", ["retention"])
    retention_module.main()
    commit_payload = capsys.readouterr().out
    assert '"audit_events": 2' in commit_payload
    assert '"dry_run": false' in commit_payload

    with Session(workbench_api_env.engine) as session:
        assert (
            session.exec(
                select(AuditEvent).where(AuditEvent.action == "retention.old.commit")
            ).first()
            is None
        )
        assert (
            session.exec(select(AuditEvent).where(AuditEvent.action == "retention.cleanup")).first()
            is not None
        )


def test_import_artifact_resolvers_reject_unmanaged_paths(tmp_path: Path) -> None:
    snapshot_root = tmp_path / "snapshots"
    attack_root = tmp_path / "attack"
    snapshot_root.mkdir()
    attack_root.mkdir()
    (snapshot_root / "provider.json").write_text("{}", encoding="utf-8")
    (attack_root / "ctid-map.json").write_text("{}", encoding="utf-8")
    active_settings = Settings(
        PROVIDER_SNAPSHOT_DIR=str(snapshot_root),
        ATTACK_ARTIFACT_DIR=str(attack_root),
    )

    assert (
        resolve_workbench_provider_snapshot_path(
            " provider.json ",
            settings=active_settings,
        )
        == snapshot_root / "provider.json"
    )
    assert (
        resolve_workbench_attack_artifact_path(
            "ctid-map.json",
            settings=active_settings,
        )
        == attack_root / "ctid-map.json"
    )

    for unsafe_snapshot in ("../provider.json", "nested/provider.json", "provider.txt"):
        with pytest.raises(ImportServiceError, match="Provider snapshot path is not allowed"):
            resolve_workbench_provider_snapshot_path(unsafe_snapshot, settings=active_settings)
    with pytest.raises(ImportServiceError, match="Provider snapshot file does not exist"):
        resolve_workbench_provider_snapshot_path("missing.json", settings=active_settings)
    with pytest.raises(ImportServiceError, match="ATT&CK artifact path is not allowed"):
        resolve_workbench_attack_artifact_path("../ctid-map.json", settings=active_settings)
    with pytest.raises(ImportServiceError, match="ATT&CK artifact file does not exist"):
        resolve_workbench_attack_artifact_path("missing.json", settings=active_settings)

    assert (
        validate_attack_import_options(
            attack_source="none",
            attack_mapping_path=None,
            attack_metadata_path=None,
        )
        == AttackSource.none
    )
    with pytest.raises(ImportServiceError, match="Unsupported ATT&CK source"):
        validate_attack_import_options(
            attack_source="unsupported",
            attack_mapping_path=None,
            attack_metadata_path=None,
        )
    with pytest.raises(ImportServiceError, match="mapping files require"):
        validate_attack_import_options(
            attack_source="none",
            attack_mapping_path=attack_root / "ctid-map.json",
            attack_metadata_path=None,
        )
    with pytest.raises(ImportServiceError, match="only support ctid-json"):
        validate_attack_import_options(
            attack_source="local-csv",
            attack_mapping_path=attack_root / "ctid-map.json",
            attack_metadata_path=None,
        )
    with pytest.raises(ImportServiceError, match="require a mapping file"):
        validate_attack_import_options(
            attack_source="ctid-json",
            attack_mapping_path=None,
            attack_metadata_path=None,
        )
    assert (
        validate_attack_import_options(
            attack_source="ctid-json",
            attack_mapping_path=attack_root / "ctid-map.json",
            attack_metadata_path=None,
        )
        == AttackSource.ctid_json
    )


def test_analysis_service_error_and_snapshot_edge_paths(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_dir = tmp_path / "cache"
    snapshot_dir = tmp_path / "snapshots"
    snapshot_dir.mkdir()
    snapshot_file = snapshot_dir / "demo_provider_snapshot.json"
    snapshot_file.write_text("{}", encoding="utf-8")
    active_settings = replace(
        workbench_api_env.client.app.state.workbench_settings,
        PROVIDER_CACHE_DIR=str(cache_dir),
        PROVIDER_SNAPSHOT_DIR=str(snapshot_dir),
        DEMO_PROVIDER_SNAPSHOT_ENABLED=True,
        NVD_API_KEY_ENV="CUSTOM_NVD_KEY",
    )

    with Session(workbench_api_env.engine) as session:
        service = AnalysisService(session, active_settings)
        assert service.default_provider_snapshot_file() == snapshot_file

        missing_snapshot_settings = replace(
            active_settings,
            PROVIDER_SNAPSHOT_DIR=str(tmp_path / "missing"),
        )
        assert (
            AnalysisService(session, missing_snapshot_settings).default_provider_snapshot_file()
            is None
        )

        with pytest.raises(WorkbenchAnalysisError, match="not a valid provider snapshot"):
            service.persist_provider_snapshot(snapshot_file, locked_provider_data=True)
        snapshot_id = service.persist_provider_snapshot(
            snapshot_file,
            locked_provider_data=False,
        )
        assert snapshot_id is not None

        captured_request: dict[str, object] = {}

        def raise_input_error(request: object) -> object:
            captured_request["nvd_api_key_env"] = getattr(request, "nvd_api_key_env", None)
            raise ValueError("bad workbench input")

        monkeypatch.setattr("app.services.analysis.prepare_analysis", raise_input_error)
        with pytest.raises(WorkbenchAnalysisError, match="bad workbench input"):
            service.analyze_import(
                input_path=tmp_path / "input.txt",
                input_type="cve-list",
                locked_provider_data=False,
                provider_snapshot_file=None,
            )
        assert captured_request["nvd_api_key_env"] == "CUSTOM_NVD_KEY"


def test_report_repository_lists_run_and_project_reports(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    graph = seed_domain_graph(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
    )
    with Session(workbench_api_env.engine) as session:
        repository = ReportRepository(session)
        first_report_id = uuid.uuid4()
        second_report_id = uuid.uuid4()
        repository.create_report(
            report_id=first_report_id,
            project_id=graph.project_id,
            analysis_run_id=graph.run_id,
            kind="summary",
            format="markdown",
            filename="summary.md",
            content_type="text/markdown",
            path="reports/summary.md",
            sha256="a" * 64,
            size_bytes=123,
        )
        repository.create_report(
            report_id=second_report_id,
            project_id=graph.project_id,
            analysis_run_id=graph.run_id,
            kind="evidence",
            format="html",
            filename="report.html",
            content_type="text/html",
            path="reports/report.html",
            sha256="b" * 64,
            size_bytes=456,
            metadata_json={"source": "test"},
        )
        session.commit()

        assert repository.get_report(first_report_id) is not None
        assert {report.id for report in repository.list_run_reports(graph.run_id)} == {
            first_report_id,
            second_report_id,
        }
        assert {
            report.filename for report in repository.list_project_reports(graph.project_id)
        } == {
            "summary.md",
            "report.html",
        }
