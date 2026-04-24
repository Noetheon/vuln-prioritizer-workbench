from __future__ import annotations

from pathlib import Path

import yaml


def test_compose_keeps_sqlite_default_and_adds_postgres_profile() -> None:
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]

    default_workbench = services["workbench"]
    assert "profiles" not in default_workbench
    assert default_workbench["environment"]["VULN_PRIORITIZER_DB_URL"].startswith("sqlite:///")
    assert (
        default_workbench["environment"]["VULN_PRIORITIZER_PROVIDER_SNAPSHOT_DIR"]
        == "/app/provider-snapshots"
    )
    assert "workbench-provider-snapshots:/app/provider-snapshots" in default_workbench["volumes"]
    assert "/app/provider-snapshots" in default_workbench["command"][2]

    postgres = services["postgres"]
    assert postgres["profiles"] == ["postgres"]
    assert postgres["healthcheck"]["test"][0] == "CMD-SHELL"

    workbench_postgres = services["workbench-postgres"]
    assert workbench_postgres["profiles"] == ["postgres"]
    assert workbench_postgres["depends_on"]["postgres"]["condition"] == "service_healthy"
    assert workbench_postgres["ports"] == ["127.0.0.1:8001:8000"]
    assert (
        workbench_postgres["environment"]["VULN_PRIORITIZER_DB_URL"]
        == "postgresql+psycopg://workbench:workbench@postgres:5432/workbench"
    )
    assert (
        workbench_postgres["environment"]["VULN_PRIORITIZER_PROVIDER_SNAPSHOT_DIR"]
        == "/app/provider-snapshots"
    )
