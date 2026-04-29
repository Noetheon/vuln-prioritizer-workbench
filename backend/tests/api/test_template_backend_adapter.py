from __future__ import annotations

import importlib

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.core.config import Settings, load_settings, parse_cors_origins
from app.main import app, create_app, custom_generate_unique_id


def test_template_backend_status_uses_versioned_api_namespace() -> None:
    client = TestClient(app)

    response = client.get("/api/v1/workbench/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["app"] == "Vuln Prioritizer Workbench"
    assert payload["core_package"] == "vuln_prioritizer"
    assert payload["legacy_api_prefix"] == "/api"
    assert payload["migration"] == {
        "phase": "template-backend-adapter",
        "legacy_workbench_mounted": False,
    }


def test_template_backend_openapi_uses_template_operation_ids() -> None:
    client = TestClient(app)

    response = client.get("/api/v1/openapi.json")

    assert response.status_code == 200
    payload = response.json()
    assert payload["info"]["title"] == "Vuln Prioritizer Workbench"
    assert payload["paths"]["/api/v1/workbench/status"]["get"]["operationId"] == (
        "workbench-template_workbench_status"
    )
    assert payload["paths"]["/api/v1/login/access-token"]["post"]["operationId"] == (
        "login-login_access_token"
    )
    assert payload["paths"]["/api/v1/users/me"]["get"]["operationId"] == ("users-read_user_me")
    assert payload["paths"]["/api/v1/utils/health-check/"]["get"]["operationId"] == (
        "utils-health_check"
    )


def test_template_backend_health_check_matches_template_utility_route() -> None:
    client = TestClient(app)

    response = client.get("/api/v1/utils/health-check/")

    assert response.status_code == 200
    assert response.json() is True


def test_template_backend_allows_configured_frontend_cors_origin() -> None:
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


def test_template_backend_can_be_configured_without_legacy_workbench_side_effects() -> None:
    selected_settings = Settings(
        API_V1_STR="/api/v1",
        PROJECT_NAME="VPW Template Adapter",
        ENVIRONMENT="local",
        LEGACY_API_PREFIX="/api",
    )
    selected_app = create_app(selected_settings)
    client = TestClient(selected_app)

    assert selected_app.state.template_settings == selected_settings
    assert client.get("/api/health").status_code == 404
    assert client.get("/api/v1/workbench/status").json()["app"] == "VPW Template Adapter"


def test_template_backend_settings_load_product_env_defaults(monkeypatch) -> None:
    monkeypatch.setenv("PROJECT_NAME", "VPW Env Shell")
    monkeypatch.setenv("ENVIRONMENT", "staging")
    monkeypatch.setenv("API_V1_STR", "/api/custom")
    monkeypatch.setenv("LEGACY_API_PREFIX", "/legacy-api")

    selected_settings = load_settings()

    assert selected_settings == Settings(
        API_V1_STR="/api/custom",
        PROJECT_NAME="VPW Env Shell",
        ENVIRONMENT="staging",
        LEGACY_API_PREFIX="/legacy-api",
        SECRET_KEY="changethis",
        ACCESS_TOKEN_EXPIRE_MINUTES=60 * 24 * 8,
        FIRST_SUPERUSER="admin@example.com",
        FIRST_SUPERUSER_PASSWORD="changethis",
        FRONTEND_HOST="http://localhost:5173",
        BACKEND_CORS_ORIGINS=(),
    )


def test_template_backend_settings_fall_back_for_unknown_environment(monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "qa")

    assert load_settings().ENVIRONMENT == "local"


def test_template_backend_settings_parse_cors_origins() -> None:
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


def test_template_backend_adapter_does_not_import_legacy_web_or_db_stack() -> None:
    modules = [
        importlib.import_module("app.main"),
        importlib.import_module("app.api.main"),
        importlib.import_module("app.api.routes.workbench"),
    ]

    for module in modules:
        imports = set(getattr(module, "__dict__", {}))
        assert "vuln_prioritizer.web" not in imports
        assert "vuln_prioritizer.db" not in imports


def test_template_operation_id_falls_back_to_route_name_without_tags() -> None:
    route = APIRoute("/debug", endpoint=lambda: None, name="debug_route")

    assert custom_generate_unique_id(route) == "debug_route"
