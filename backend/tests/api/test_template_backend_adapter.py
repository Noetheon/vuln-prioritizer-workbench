from __future__ import annotations

import importlib

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.core.config import Settings, load_settings
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
    )


def test_template_backend_settings_fall_back_for_unknown_environment(monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "qa")

    assert load_settings().ENVIRONMENT == "local"


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
