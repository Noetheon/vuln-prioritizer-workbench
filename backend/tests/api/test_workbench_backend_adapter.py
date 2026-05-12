from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.api.main import PUBLIC_API_ROUTE_PATHS
from app.api.routes.workbench import _database_readiness
from app.core.config import (
    Settings,
    build_database_uri,
    load_settings,
    parse_allowed_hosts,
    parse_cors_origins,
    settings,
)
from app.core.migration_bootstrap import ALEMBIC_HEAD
from app.main import app, create_app, custom_generate_unique_id


def test_workbench_backend_status_uses_versioned_api_namespace(tmp_path) -> None:
    selected_app = create_app(
        Settings(SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'status-workbench.db'}")
    )
    SQLModel.metadata.create_all(selected_app.state.workbench_engine)
    _stamp_alembic_head(selected_app.state.workbench_engine)
    client = TestClient(selected_app)

    response = client.get("/api/v1/workbench/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert payload["app"] == "Vuln Prioritizer Workbench"
    assert payload["core_package"] == "vuln_prioritizer"
    assert payload["database_status"] == "ready"
    assert payload["schema_status"] == "ready"
    assert set(payload) == {
        "status",
        "app",
        "core_package",
        "core_version",
        "database_status",
        "schema_status",
    }


def test_workbench_backend_openapi_uses_stable_operation_ids() -> None:
    client = TestClient(app)

    response = client.get("/api/v1/openapi.json")

    assert response.status_code == 200
    payload = response.json()
    assert payload["info"]["title"] == "Vuln Prioritizer Workbench"
    assert payload["paths"]["/api/v1/workbench/health"]["get"]["operationId"] == (
        "workbench-workbench_health"
    )
    assert payload["paths"]["/api/v1/workbench/status"]["get"]["operationId"] == (
        "workbench-workbench_status"
    )
    assert payload["paths"]["/api/v1/utils/health-check/"]["get"]["operationId"] == (
        "utils-health_check"
    )
    assert "/api/v1/login/access-token" not in payload["paths"]
    assert "/api/v1/users/me" not in payload["paths"]
    assert "/api/v1/api-tokens/" not in payload["paths"]


def test_workbench_backend_openapi_documents_error_envelope() -> None:
    client = TestClient(app)

    response = client.get("/api/v1/openapi.json")

    assert response.status_code == 200
    payload = response.json()
    error_schema = payload["components"]["schemas"]["ApiErrorEnvelope"]
    assert error_schema["required"] == ["code", "message", "details", "detail"]
    assert set(error_schema["properties"]) == {
        "code",
        "message",
        "details",
        "detail",
        "trace_id",
    }
    assert payload["paths"]["/api/v1/projects/"]["post"]["responses"]["422"]["content"][
        "application/json"
    ]["schema"] == {"$ref": "#/components/schemas/ApiErrorEnvelope"}


def test_workbench_backend_openapi_omits_oauth_security_for_local_runtime(tmp_path) -> None:
    selected_app = create_app(
        Settings(
            API_V1_STR="/api/custom",
            SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'custom-openapi.db'}",
        )
    )
    client = TestClient(selected_app)

    response = client.get("/api/custom/openapi.json")

    assert response.status_code == 200
    security_schemes = response.json()["components"].get("securitySchemes", {})
    assert "OAuth2PasswordBearer" not in security_schemes


def test_workbench_api_routes_require_local_actor_unless_allowlisted() -> None:
    public_paths: set[str] = set()
    unprotected_paths: list[str] = []

    for route in app.routes:
        if not isinstance(route, APIRoute) or not route.path.startswith("/api/v1"):
            continue
        if route.path in PUBLIC_API_ROUTE_PATHS:
            public_paths.add(route.path)
            continue
        dependency_names = _route_dependency_names(route)
        if dependency_names.isdisjoint({"dependency", "get_local_actor"}):
            unprotected_paths.append(f"{','.join(sorted(route.methods))} {route.path}")

    assert public_paths == PUBLIC_API_ROUTE_PATHS
    assert unprotected_paths == []


def test_workbench_backend_rejects_invalid_host_header() -> None:
    client = TestClient(app)

    response = client.get(
        "/api/v1/workbench/health",
        headers={"host": "evil.example"},
    )

    assert response.status_code == 400
    assert response.text == "Invalid host header"


@pytest.mark.parametrize("host", ["testserver", "localhost", "127.0.0.1"])
def test_workbench_backend_allows_local_and_testclient_hosts(host: str) -> None:
    client = TestClient(app)

    response = client.get(
        "/api/v1/workbench/health",
        headers={"host": host},
    )

    assert response.status_code == 200


def test_workbench_backend_health_check_matches_utility_route() -> None:
    client = TestClient(app)

    response = client.get("/api/v1/utils/health-check/")

    assert response.status_code == 200
    assert response.json() is True


def test_workbench_backend_http_errors_include_stable_envelope() -> None:
    client = TestClient(app)

    response = client.get("/api/v1/items/")

    assert response.status_code == 404
    payload = response.json()
    assert payload["code"] == "not_found"
    assert payload["message"] == "Not Found"
    assert payload["details"] == {}
    assert payload["detail"] == "Not Found"


def test_workbench_backend_validation_errors_include_redacted_envelope() -> None:
    selected_app = create_app(Settings(ENVIRONMENT="local"))

    @selected_app.get("/debug/{item_id}")
    def _debug_item(item_id: int) -> dict[str, int]:
        return {"item_id": item_id}

    client = TestClient(selected_app)

    response = client.get("/debug/not-a-number")

    assert response.status_code == 422
    payload = response.json()
    assert payload["code"] == "request_validation_failed"
    assert payload["message"] == "Request validation failed."
    assert "errors" in payload["details"]
    assert "/Users/" not in response.text
    assert "token" not in response.text.lower()


def test_workbench_backend_allows_configured_frontend_cors_origin() -> None:
    client = TestClient(app)

    response = client.options(
        "/api/v1/workbench/status",
        headers={
            "origin": "http://localhost:5173",
            "access-control-request-method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_workbench_backend_can_be_configured_without_legacy_state_aliases() -> None:
    selected_settings = Settings(
        API_V1_STR="/api/v1",
        PROJECT_NAME="VPW Workbench Adapter",
        ENVIRONMENT="local",
    )
    selected_app = create_app(selected_settings)
    client = TestClient(selected_app)

    assert selected_app.state.workbench_settings == selected_settings
    assert not hasattr(selected_app.state, "template_settings")
    assert client.get("/api/health").status_code == 404
    assert client.get("/api/v1/workbench/health").json()["status"] == "ok"


def test_workbench_backend_create_app_uses_isolated_settings_db_and_local_principal(
    tmp_path,
) -> None:
    selected_settings = Settings(
        API_V1_STR="/api/v1",
        PROJECT_NAME="Isolated VPW Adapter",
        ENVIRONMENT="local",
        SECRET_KEY="selected-workbench-secret-0123456789abcdef",
        LOCAL_WORKBENCH_USER_EMAIL="selected-admin@example.test",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'selected-workbench.db'}",
    )
    selected_app = create_app(selected_settings)
    SQLModel.metadata.create_all(selected_app.state.workbench_engine)
    _stamp_alembic_head(selected_app.state.workbench_engine)
    client = TestClient(selected_app)

    global_login = client.post(
        "/api/v1/login/access-token",
        data={"username": settings.LOCAL_WORKBENCH_USER_EMAIL, "password": "unused"},
    )
    project = client.post(
        "/api/v1/projects/",
        json={"name": "Selected Settings Project", "description": None},
    )
    status = client.get("/api/v1/workbench/status")

    assert global_login.status_code == 404
    assert project.status_code == 200, project.text
    assert project.json()["name"] == "Selected Settings Project"
    assert status.status_code == 200
    assert status.json()["status"] == "ready"


def test_workbench_backend_readiness_fails_closed_for_partial_schema() -> None:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    _stamp_alembic_head(engine)
    try:
        with Session(engine) as session:
            assert _database_readiness(session) == ("ready", "ready")
        with engine.begin() as connection:
            connection.execute(text("DROP TABLE finding"))
        with Session(engine) as session:
            assert _database_readiness(session) == ("ready", "not_ready")
    finally:
        engine.dispose()


def test_workbench_backend_settings_load_product_env_defaults(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PROJECT_NAME", "VPW Env Shell")
    monkeypatch.setenv("ENVIRONMENT", "staging")
    monkeypatch.setenv("API_V1_STR", "/api/custom")
    monkeypatch.setenv("SECRET_KEY", "workbench-shell-secret-0123456789abcdef")
    monkeypatch.setenv("FRONTEND_HOST", "https://workbench.example.com")
    monkeypatch.setenv("VULN_PRIORITIZER_NVD_API_KEY_ENV", "CUSTOM_NVD_KEY")

    selected_settings = load_settings()

    assert selected_settings == Settings(
        API_V1_STR="/api/custom",
        PROJECT_NAME="VPW Env Shell",
        ENVIRONMENT="staging",
        SECRET_KEY="workbench-shell-secret-0123456789abcdef",
        LOCAL_WORKBENCH_USER_EMAIL="local@workbench.test",
        FRONTEND_HOST="https://workbench.example.com",
        BACKEND_CORS_ORIGINS=(),
        NVD_API_KEY_ENV="CUSTOM_NVD_KEY",
    )


def test_workbench_settings_use_workbench_storage_defaults(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    for name in (
        "SQLALCHEMY_DATABASE_URI",
        "DATABASE_URL",
        "POSTGRES_SERVER",
        "IMPORT_UPLOAD_DIR",
        "REPORT_DIR",
        "PROVIDER_CACHE_DIR",
    ):
        monkeypatch.delenv(name, raising=False)

    selected_settings = load_settings()

    assert build_database_uri() == "sqlite:///./workbench.db"
    assert selected_settings.SQLALCHEMY_DATABASE_URI == "sqlite:///./workbench.db"
    assert selected_settings.IMPORT_UPLOAD_DIR == "data/workbench-import-uploads"
    assert selected_settings.REPORT_DIR == "data/workbench-reports"
    assert selected_settings.PROVIDER_CACHE_DIR == "data/workbench-provider-cache"


def test_workbench_settings_ignore_legacy_storage_without_explicit_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    for name in (
        "SQLALCHEMY_DATABASE_URI",
        "DATABASE_URL",
        "POSTGRES_SERVER",
        "IMPORT_UPLOAD_DIR",
        "REPORT_DIR",
        "PROVIDER_CACHE_DIR",
    ):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "template.db").write_text("", encoding="utf-8")
    for legacy_dir in (
        tmp_path / "data" / "template-import-uploads",
        tmp_path / "data" / "workbench-reports",
        tmp_path / "data" / "template-provider-cache",
    ):
        legacy_dir.mkdir(parents=True)
        (legacy_dir / ".keep").write_text("legacy data\n", encoding="utf-8")

    selected_settings = load_settings()

    assert selected_settings.SQLALCHEMY_DATABASE_URI == "sqlite:///./workbench.db"
    assert selected_settings.IMPORT_UPLOAD_DIR == "data/workbench-import-uploads"
    assert selected_settings.REPORT_DIR == "data/workbench-reports"
    assert selected_settings.PROVIDER_CACHE_DIR == "data/workbench-provider-cache"


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_workbench_backend_settings_reject_non_local_default_secrets(
    environment: str,
) -> None:
    with pytest.raises(ValueError, match="SECRET_KEY"):
        Settings(ENVIRONMENT=environment)


def test_workbench_backend_load_settings_rejects_non_local_default_secret_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("SECRET_KEY", raising=False)

    with pytest.raises(ValueError, match="SECRET_KEY"):
        load_settings()


@pytest.mark.parametrize("password", ["", "postgres", "workbench", "changethis"])
def test_workbench_backend_load_settings_rejects_non_local_default_postgres_password(
    monkeypatch: pytest.MonkeyPatch,
    password: str,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("POSTGRES_SERVER", "db")
    monkeypatch.setenv("POSTGRES_PASSWORD", password)
    monkeypatch.setenv("SECRET_KEY", "production-secret-key-0123456789abcdef")

    with pytest.raises(ValueError, match="POSTGRES_PASSWORD must be set"):
        load_settings()


def test_workbench_backend_build_database_uri_accepts_non_default_postgres_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("POSTGRES_SERVER", "db")
    monkeypatch.setenv("POSTGRES_PORT", "5432")
    monkeypatch.setenv("POSTGRES_DB", "workbench")
    monkeypatch.setenv("POSTGRES_USER", "workbench")
    monkeypatch.setenv("POSTGRES_PASSWORD", "non-default-production-password")

    assert build_database_uri() == (
        "postgresql+psycopg://workbench:non-default-production-password@db:5432/workbench"
    )


def test_workbench_backend_settings_reject_local_default_secrets_with_public_hosts() -> None:
    with pytest.raises(ValueError, match="non-local ALLOWED_HOSTS"):
        Settings(ENVIRONMENT="local", ALLOWED_HOSTS=("localhost", "workbench.example.com"))


def test_workbench_backend_settings_reject_weak_non_default_production_secrets() -> None:
    with pytest.raises(ValueError, match="strong non-default secret values"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="short-secret",
            FRONTEND_HOST="https://workbench.example.com",
            ALLOWED_HOSTS=("workbench.example.com",),
        )


def test_workbench_backend_settings_reject_unknown_environment(monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "qa")

    with pytest.raises(ValueError, match="ENVIRONMENT must be one of"):
        load_settings()


def test_workbench_backend_settings_reject_unsafe_nvd_api_key_env_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULN_PRIORITIZER_NVD_API_KEY_ENV", "not-safe")

    with pytest.raises(ValueError, match="NVD API key environment variable name"):
        load_settings()


def test_workbench_backend_settings_trim_environment_before_validation(monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", " production ")
    monkeypatch.setenv("SECRET_KEY", "workbench-shell-secret-0123456789abcdef")
    monkeypatch.setenv("FRONTEND_HOST", "https://workbench.example.com")

    assert load_settings().ENVIRONMENT == "production"


def test_workbench_backend_settings_parse_cors_origins() -> None:
    assert parse_cors_origins(" http://localhost:5173/, http://127.0.0.1:5173 ") == (
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    )
    selected_settings = Settings(
        FRONTEND_HOST="http://localhost:5173/",
        BACKEND_CORS_ORIGINS=("http://localhost:5173", "http://127.0.0.1:5173"),
    )

    assert selected_settings.all_cors_origins == (
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    )


@pytest.mark.parametrize(
    "frontend_host, origins, message",
    [
        ("https://workbench.example.com", ("*",), "exact origins"),
        ("http://workbench.example.com", (), "https"),
        ("https://localhost", (), "localhost"),
        ("https://workbench.example.com/path", (), "entries must be origins"),
    ],
)
def test_workbench_backend_rejects_unsafe_non_local_cors(
    frontend_host: str,
    origins: tuple[str, ...],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="workbench-shell-secret-0123456789abcdef",
            FRONTEND_HOST=frontend_host,
            BACKEND_CORS_ORIGINS=origins,
            ALLOWED_HOSTS=("workbench.example.com",),
        )


def test_workbench_backend_accepts_exact_https_non_local_cors() -> None:
    selected_settings = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="workbench-shell-secret-0123456789abcdef",
        FRONTEND_HOST="https://workbench.example.com",
        BACKEND_CORS_ORIGINS=("https://api.workbench.example.com",),
        ALLOWED_HOSTS=("workbench.example.com",),
    )

    assert selected_settings.all_cors_origins == (
        "https://api.workbench.example.com",
        "https://workbench.example.com",
    )


def test_workbench_backend_settings_parse_allowed_hosts() -> None:
    assert parse_allowed_hosts(" Localhost, 127.0.0.1, TESTSERVER ") == (
        "localhost",
        "127.0.0.1",
        "testserver",
    )
    selected_settings = Settings(
        ALLOWED_HOSTS=("localhost", "localhost", "api.localhost"),
    )

    assert selected_settings.ALLOWED_HOSTS == ("localhost", "api.localhost")


@pytest.mark.parametrize(
    "allowed_hosts",
    [
        ("http://localhost",),
        ("localhost:8000",),
        ("::1",),
        ("*",),
        (),
    ],
)
def test_workbench_backend_settings_reject_malformed_allowed_hosts(
    allowed_hosts: tuple[str, ...],
) -> None:
    with pytest.raises(ValueError, match="ALLOWED_HOSTS"):
        Settings(ALLOWED_HOSTS=allowed_hosts)


def test_workbench_backend_hides_docs_and_openapi_outside_local_by_default() -> None:
    selected_app = create_app(
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="workbench-shell-secret-0123456789abcdef",
            FRONTEND_HOST="https://workbench.example.com",
            ALLOWED_HOSTS=("workbench.example.com",),
            RATE_LIMIT_ENABLED=False,
        )
    )
    client = TestClient(selected_app)

    assert client.get("/docs", headers={"host": "workbench.example.com"}).status_code == 404
    assert (
        client.get(
            "/api/v1/openapi.json",
            headers={"host": "workbench.example.com"},
        ).status_code
        == 404
    )
    assert (
        client.get(
            "/api/v1/workbench/health",
            headers={"host": "workbench.example.com"},
        ).status_code
        == 200
    )
    status = client.get(
        "/api/v1/workbench/status",
        headers={"host": "workbench.example.com"},
    )
    assert status.status_code != 401


def test_workbench_backend_non_local_startup_rejects_stale_schema(tmp_path) -> None:
    selected_app = create_app(
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="workbench-shell-secret-0123456789abcdef",
            FRONTEND_HOST="https://workbench.example.com",
            ALLOWED_HOSTS=("workbench.example.com",),
            SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'stale.db'}",
        )
    )

    with pytest.raises(RuntimeError, match="missing alembic_version|missing model tables"):
        with TestClient(selected_app):
            pass


def test_workbench_backend_can_explicitly_expose_openapi_for_client_generation() -> None:
    selected_app = create_app(
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="workbench-shell-secret-0123456789abcdef",
            FRONTEND_HOST="https://workbench.example.com",
            ALLOWED_HOSTS=("workbench.example.com",),
            API_DOCS_ENABLED=True,
            RATE_LIMIT_ENABLED=False,
        )
    )
    client = TestClient(selected_app)

    response = client.get(
        "/api/v1/openapi.json",
        headers={"host": "workbench.example.com"},
    )

    assert response.status_code == 200
    assert response.json()["info"]["title"] == "Vuln Prioritizer Workbench"


def _stamp_alembic_head(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:version_num)"),
            {"version_num": ALEMBIC_HEAD},
        )


def _route_dependency_names(route: APIRoute) -> set[str]:
    dependency_names: set[str] = set()

    def visit(dependant: object) -> None:
        for dependency in getattr(dependant, "dependencies", []):
            call = getattr(dependency, "call", None)
            dependency_names.add(getattr(call, "__name__", repr(call)))
            visit(dependency)

    visit(route.dependant)
    return dependency_names


def test_workbench_backend_adapter_does_not_import_legacy_web_or_db_stack() -> None:
    modules = [
        importlib.import_module("app.main"),
        importlib.import_module("app.api.main"),
        importlib.import_module("app.api.routes.workbench"),
    ]

    for module in modules:
        imports = set(getattr(module, "__dict__", {}))
        assert "vuln_prioritizer.web" not in imports
        assert "vuln_prioritizer.db" not in imports


def test_workbench_operation_id_falls_back_to_route_name_without_tags() -> None:
    route = APIRoute("/debug", endpoint=lambda: None, name="debug_route")

    assert custom_generate_unique_id(route) == "debug_route"
