from __future__ import annotations

from pathlib import Path

import yaml


def test_compose_uses_template_shell_and_keeps_profiled_legacy_postgres() -> None:
    compose = yaml.safe_load(Path("compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]

    backend = services["backend"]
    assert "profiles" not in backend
    assert backend["depends_on"]["db"]["condition"] == "service_healthy"
    assert backend["environment"]["PROJECT_NAME"].startswith("${PROJECT_NAME:-Vuln Prioritizer")
    assert "/api/v1/workbench/status" in backend["healthcheck"]["test"][3]

    frontend = services["frontend"]
    assert "profiles" not in frontend
    assert frontend["depends_on"]["backend"]["condition"] == "service_healthy"

    db = services["db"]
    assert db["environment"]["POSTGRES_DB"] == "${POSTGRES_DB:-workbench}"
    assert db["healthcheck"]["test"][0] == "CMD-SHELL"

    workbench_postgres = services["workbench-postgres"]
    assert workbench_postgres["profiles"] == ["postgres"]
    assert workbench_postgres["depends_on"]["db"]["condition"] == "service_healthy"
    assert (
        workbench_postgres["environment"]["VULN_PRIORITIZER_DB_URL"]
        == "postgresql+psycopg://${POSTGRES_USER:-workbench}:${POSTGRES_PASSWORD:-workbench}@db:5432/${POSTGRES_DB:-workbench}"
    )
    assert (
        workbench_postgres["environment"]["VULN_PRIORITIZER_PROVIDER_SNAPSHOT_DIR"]
        == "/app/provider-snapshots"
    )


def test_compose_override_exposes_template_shell_and_frontend_ports() -> None:
    override = yaml.safe_load(Path("compose.override.yml").read_text(encoding="utf-8"))
    services = override["services"]

    assert services["backend"]["ports"] == ["127.0.0.1:8000:8000"]
    assert "app.main:app" in services["backend"]["command"]
    assert services["frontend"]["ports"] == ["127.0.0.1:5173:80"]
    assert services["workbench-postgres"]["ports"] == ["127.0.0.1:8001:8000"]
