from __future__ import annotations

from pathlib import Path

import yaml


def test_backend_dockerfile_prepares_template_quickstart_runtime_dirs() -> None:
    dockerfile = Path("backend/Dockerfile").read_text(encoding="utf-8")

    assert "/app/template-import-uploads" in dockerfile
    assert "/app/template-reports" in dockerfile
    assert "/app/template-provider-cache" in dockerfile
    assert "chown -R workbench:workbench /app" in dockerfile


def test_compose_uses_template_shell_without_legacy_runtime_services() -> None:
    compose = yaml.safe_load(Path("compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]

    backend = services["backend"]
    assert "profiles" not in backend
    assert backend["depends_on"]["db"]["condition"] == "service_healthy"
    assert backend["environment"]["PROJECT_NAME"].startswith("${PROJECT_NAME:-Vuln Prioritizer")
    assert "http://127.0.0.1:5173" in backend["environment"]["BACKEND_CORS_ORIGINS"]
    assert backend["environment"]["IMPORT_UPLOAD_DIR"] == "/app/template-import-uploads"
    assert backend["environment"]["REPORT_DIR"] == "/app/template-reports"
    assert backend["environment"]["PROVIDER_SNAPSHOT_DIR"] == "/app/provider-snapshots"
    assert backend["environment"]["PROVIDER_CACHE_DIR"] == "/app/template-provider-cache"
    assert backend["environment"]["ATTACK_ARTIFACT_DIR"] == "/app/examples/attack"
    assert "template-import-uploads:/app/template-import-uploads" in backend["volumes"]
    assert "template-reports:/app/template-reports" in backend["volumes"]
    assert "template-provider-snapshots:/app/provider-snapshots" in backend["volumes"]
    assert "template-provider-cache:/app/template-provider-cache" in backend["volumes"]
    assert "./data:/app/examples:ro" in backend["volumes"]
    assert "/api/v1/workbench/status" in backend["healthcheck"]["test"][3]

    frontend = services["frontend"]
    assert "profiles" not in frontend
    assert frontend["depends_on"]["backend"]["condition"] == "service_healthy"

    db = services["db"]
    assert db["environment"]["POSTGRES_DB"] == "${POSTGRES_DB:-workbench}"
    assert db["healthcheck"]["test"][0] == "CMD-SHELL"

    assert "workbench-postgres" not in services
    assert "provider-scheduler" not in services


def test_legacy_compose_keeps_profiled_postgres_compatibility_runtime() -> None:
    legacy_compose = yaml.safe_load(Path("compose.legacy.yml").read_text(encoding="utf-8"))
    services = legacy_compose["services"]

    workbench_postgres = services["workbench-postgres"]
    assert workbench_postgres["profiles"] == ["legacy-postgres"]
    assert workbench_postgres["depends_on"]["db"]["condition"] == "service_healthy"
    assert (
        workbench_postgres["environment"]["VULN_PRIORITIZER_DB_URL"]
        == "postgresql+psycopg://${POSTGRES_USER:-workbench}:${POSTGRES_PASSWORD:-workbench}@db:5432/${POSTGRES_DB:-workbench}"
    )
    assert (
        workbench_postgres["environment"]["VULN_PRIORITIZER_PROVIDER_SNAPSHOT_DIR"]
        == "/app/provider-snapshots"
    )
    assert workbench_postgres["environment"]["VULN_PRIORITIZER_ALLOWED_HOSTS"] == (
        "${VULN_PRIORITIZER_ALLOWED_HOSTS:-127.0.0.1,localhost,workbench-postgres}"
    )
    assert workbench_postgres["ports"] == ["127.0.0.1:8001:8000"]

    scheduler = services["provider-scheduler"]
    assert scheduler["profiles"] == ["legacy-postgres"]
    assert scheduler["depends_on"]["workbench-postgres"]["condition"] == "service_healthy"
    assert scheduler["command"] == ["python", "-m", "vuln_prioritizer.provider_scheduler"]
    assert scheduler["read_only"] is True
    assert scheduler["cap_drop"] == ["ALL"]
    assert scheduler["security_opt"] == ["no-new-privileges:true"]
    scheduler_env = scheduler["environment"]
    assert scheduler_env["VULN_PRIORITIZER_PROVIDER_UPDATE_BASE_URL"] == (
        "http://workbench-postgres:8000"
    )
    assert scheduler_env["VULN_PRIORITIZER_PROVIDER_UPDATE_INTERVAL_SECONDS"] == (
        "${VULN_PRIORITIZER_PROVIDER_UPDATE_INTERVAL_SECONDS:-86400}"
    )
    assert scheduler_env["VULN_PRIORITIZER_PROVIDER_UPDATE_CACHE_ONLY"] == (
        "${VULN_PRIORITIZER_PROVIDER_UPDATE_CACHE_ONLY:-true}"
    )


def test_compose_override_exposes_template_shell_and_frontend_ports() -> None:
    override = yaml.safe_load(Path("compose.override.yml").read_text(encoding="utf-8"))
    services = override["services"]
    backend_command = "\n".join(services["backend"]["command"])

    assert services["backend"]["ports"] == ["127.0.0.1:8000:8000"]
    assert "cp -n /app/examples/*provider_snapshot*.json /app/provider-snapshots/" in (
        backend_command
    )
    assert "init_db(session)" in backend_command
    assert "app.main:app" in backend_command
    assert services["frontend"]["ports"] == ["127.0.0.1:5173:80"]
    assert "workbench-postgres" not in services


def test_docker_demo_smoke_runs_quickstart_api_import() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")
    script = Path("scripts/docker_quickstart_api_smoke.py").read_text(encoding="utf-8")

    docker_smoke_block = makefile.split("docker-demo-smoke:", 1)[1].split(
        "docker-postgres-migration-smoke:",
        1,
    )[0]
    assert "$(PYTHON) scripts/docker_quickstart_api_smoke.py" in docker_smoke_block
    assert "locked_provider_data" in script
    assert "demo_provider_snapshot.json" in script
    assert "providers/update-jobs" in script


def test_frontend_nginx_serves_security_headers_for_static_and_404_routes() -> None:
    nginx_conf = Path("frontend/nginx.conf").read_text(encoding="utf-8")
    blocked_routes = Path("frontend/nginx-backend-not-found.conf").read_text(encoding="utf-8")

    assert "add_header Content-Security-Policy" in nginx_conf
    assert "always;" in nginx_conf
    assert "default-src 'self'" in nginx_conf
    assert "object-src 'none'" in nginx_conf
    assert "frame-ancestors 'none'" in nginx_conf
    assert "connect-src 'self' http://localhost:8000 http://127.0.0.1:8000" in nginx_conf
    assert 'add_header X-Content-Type-Options "nosniff" always;' in nginx_conf
    assert 'add_header X-Frame-Options "DENY" always;' in nginx_conf
    assert 'add_header Referrer-Policy "same-origin" always;' in nginx_conf
    assert 'add_header Cross-Origin-Opener-Policy "same-origin" always;' in nginx_conf
    assert (
        'add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), '
        'payment=(), usb=()" always;'
    ) in nginx_conf
    assert "include /etc/nginx/extra-conf.d/*.conf;" in nginx_conf
    assert "location /api" in blocked_routes
    assert "return 404;" in blocked_routes
