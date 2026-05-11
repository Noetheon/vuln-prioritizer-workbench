from __future__ import annotations

import ast
import os
import subprocess
import tarfile
from collections import deque
from pathlib import Path
from typing import Any

import yaml

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
APP_ROOT = BACKEND_ROOT / "app"
SRC_ROOT = BACKEND_ROOT / "src"
SRC_PACKAGE_ROOT = SRC_ROOT / "vuln_prioritizer"

REMOVED_LEGACY_RUNTIME_PATHS = (
    SRC_PACKAGE_ROOT / "api",
    SRC_PACKAGE_ROOT / "web",
    SRC_PACKAGE_ROOT / "db",
    SRC_PACKAGE_ROOT / "provider_scheduler.py",
    SRC_PACKAGE_ROOT / "workbench_config.py",
    SRC_PACKAGE_ROOT / "commands" / "db.py",
    SRC_PACKAGE_ROOT / "commands" / "web.py",
    REPO_ROOT / "compose.legacy.yml",
)
LEGACY_RUNTIME_PREFIXES = (
    "vuln_prioritizer.api",
    "vuln_prioritizer.web",
    "vuln_prioritizer.db",
    "vuln_prioritizer.services.workbench_",
    "vuln_prioritizer.provider_scheduler",
    "vuln_prioritizer.workbench_config",
)
LEGACY_RUNTIME_STARTERS = (
    "vuln-prioritizer web serve",
    "vuln_prioritizer.api.app",
    "vuln_prioritizer.provider_scheduler",
    "docker-postgres-migration-smoke",
    "compose.legacy.yml",
)


def _module_name(path: Path) -> str:
    if path.is_relative_to(APP_ROOT):
        relative = path.relative_to(BACKEND_ROOT).with_suffix("")
    else:
        relative = path.relative_to(SRC_ROOT).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _module_paths() -> dict[str, Path]:
    paths = sorted(APP_ROOT.rglob("*.py")) + sorted(SRC_PACKAGE_ROOT.rglob("*.py"))
    return {_module_name(path): path for path in paths}


def _resolve_import_from_module(
    current_module: str, path: Path, node: ast.ImportFrom
) -> str | None:
    if node.level == 0:
        return node.module

    package = current_module if path.name == "__init__.py" else current_module.rsplit(".", 1)[0]
    package_parts = package.split(".") if package else []
    if node.level > len(package_parts) + 1:
        return None
    prefix_parts = package_parts[: len(package_parts) - node.level + 1]
    if node.module:
        prefix_parts.extend(node.module.split("."))
    return ".".join(prefix_parts) if prefix_parts else None


def _raw_imports(path: Path) -> set[str]:
    current_module = _module_name(path)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = _resolve_import_from_module(current_module, path, node)
            if module is None:
                continue
            imports.add(module)
            imports.update(f"{module}.{alias.name}" for alias in node.names if alias.name != "*")
    return imports


def _nearest_known_module(imported: str, modules: dict[str, Path]) -> str | None:
    if not (imported == "app" or imported.startswith(("app.", "vuln_prioritizer"))):
        return None
    parts = imported.split(".")
    while parts:
        candidate = ".".join(parts)
        if candidate in modules:
            return candidate
        parts.pop()
    return None


def _reachable_modules_from_template_backend() -> set[str]:
    modules = _module_paths()
    queue = deque(
        sorted(module for module in modules if module == "app" or module.startswith("app."))
    )
    reachable = set(queue)

    while queue:
        module = queue.popleft()
        for imported in _raw_imports(modules[module]):
            dependency = _nearest_known_module(imported, modules)
            if dependency is not None and dependency not in reachable:
                reachable.add(dependency)
                queue.append(dependency)

    return reachable


def _matches_legacy_runtime(module: str) -> bool:
    return any(module == prefix or module.startswith(prefix) for prefix in LEGACY_RUNTIME_PREFIXES)


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(_as_text(item) for item in value)
    if isinstance(value, dict):
        return "\n".join(f"{key}: {_as_text(item)}" for key, item in value.items())
    return str(value)


def _read_repo_text(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def test_legacy_workbench_runtime_source_is_removed() -> None:
    remaining_paths = [path for path in REMOVED_LEGACY_RUNTIME_PATHS if path.exists()]
    remaining_workbench_services = sorted(SRC_PACKAGE_ROOT.glob("services/workbench_*.py"))

    assert remaining_paths == []
    assert remaining_workbench_services == []


def test_template_backend_import_graph_does_not_reach_legacy_runtime() -> None:
    reachable = _reachable_modules_from_template_backend()

    legacy_runtime_modules = sorted(
        module for module in reachable if _matches_legacy_runtime(module)
    )

    assert legacy_runtime_modules == []


def test_template_runtime_names_are_documented_compatibility_aliases() -> None:
    analysis_service = _read_repo_text("backend/app/services/analysis.py")
    import_artifacts = _read_repo_text("backend/app/services/import_artifacts.py")
    provider_updates = _read_repo_text("backend/app/services/provider_updates.py")
    app_state = _read_repo_text("backend/app/core/app_state.py")
    public_deployment = _read_repo_text("docs/workbench-public-deployment.md")
    frontend_defaults = _read_repo_text("frontend/src/lib/app-defaults.ts")

    assert "class WorkbenchAnalysisError" in analysis_service
    assert "class WorkbenchAnalysisResult" in analysis_service
    assert "DEFAULT_WORKBENCH_PROVIDER_SNAPSHOT" in analysis_service
    assert "TemplateAnalysisError = WorkbenchAnalysisError" in analysis_service
    assert "TemplateAnalysisResult = WorkbenchAnalysisResult" in analysis_service
    assert "DEFAULT_TEMPLATE_PROVIDER_SNAPSHOT = DEFAULT_WORKBENCH_PROVIDER_SNAPSHOT" in (
        analysis_service
    )

    assert "Compatibility aliases for template-era local integrations." in import_artifacts
    assert "resolve_template_provider_snapshot_path" in import_artifacts
    assert "Compatibility aliases for template-era local integrations." in provider_updates
    assert "TemplateProviderUpdateConflict = ProviderUpdateConflict" in provider_updates

    assert 'LEGACY_SETTINGS_STATE_KEY = "template_settings"' in app_state
    assert "Backward-compatible aliases for older local tests and scripts." in app_state
    normalized_public_deployment = " ".join(public_deployment.split())
    assert "historical compatibility names" in normalized_public_deployment
    assert "separate template-era Workbench runtime" in normalized_public_deployment
    assert "WorkbenchReportFormat" in frontend_defaults
    assert "TemplateReportFormat" not in frontend_defaults

    active_runtime_docs = [
        _read_repo_text("backend/app/__init__.py"),
        _read_repo_text("backend/app/api/routes/__init__.py"),
        _read_repo_text("backend/app/core/security.py"),
        _read_repo_text("backend/app/repositories/__init__.py"),
        _read_repo_text("backend/app/services/__init__.py"),
        _read_repo_text("backend/app/services/reports.py"),
    ]
    forbidden_phrases = (
        "Template Workbench",
        "Template-stack",
        "Template-style",
        "Template-aligned",
    )
    violations = [
        phrase for text in active_runtime_docs for phrase in forbidden_phrases if phrase in text
    ]

    assert violations == []


def test_import_service_modules_do_not_import_http_or_route_boundaries() -> None:
    violations: dict[str, list[str]] = {}
    blocked_prefixes = ("fastapi", "starlette", "app.api")

    for path in sorted((APP_ROOT / "services").glob("import*.py")):
        imports = sorted(
            imported
            for imported in _raw_imports(path)
            if any(
                imported == prefix or imported.startswith(f"{prefix}.")
                for prefix in blocked_prefixes
            )
        )
        if imports:
            violations[str(path.relative_to(BACKEND_ROOT))] = imports

    assert violations == {}


def test_default_compose_services_start_only_active_backend_runtime() -> None:
    compose = yaml.safe_load((REPO_ROOT / "compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    volumes = compose["volumes"]
    backend_environment = services["backend"]["environment"]
    backend_healthcheck = _as_text(services["backend"]["healthcheck"])

    legacy_starters = {
        name: _as_text(service)
        for name, service in services.items()
        if any(marker in _as_text(service) for marker in LEGACY_RUNTIME_STARTERS)
    }

    assert "backend" in services
    assert "frontend" in services
    assert "workbench-postgres" not in services
    assert "provider-scheduler" not in services
    assert backend_environment["ALLOWED_HOSTS"] == (
        "${ALLOWED_HOSTS:-localhost,127.0.0.1,testserver,backend}"
    )
    assert backend_environment["API_DOCS_ENABLED"] == "${API_DOCS_ENABLED:-}"
    assert backend_environment["SQLALCHEMY_DATABASE_URI"] == ""
    assert backend_environment["RATE_LIMIT_ENABLED"] == "${RATE_LIMIT_ENABLED:-true}"
    assert backend_environment["MAX_UPLOAD_MB"] == "${MAX_UPLOAD_MB:-25}"
    assert backend_environment["MAX_REPORT_MB"] == "${MAX_REPORT_MB:-50}"
    assert backend_environment["MAX_REPORTS_PER_RUN"] == "${MAX_REPORTS_PER_RUN:-20}"
    assert backend_environment["DECISION_API_MAX_FINDINGS"] == (
        "${DECISION_API_MAX_FINDINGS:-1000}"
    )
    assert backend_environment["POSTGRES_PASSWORD"].startswith(
        "${POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD"
    )
    assert backend_environment["LOGIN_RATE_LIMIT_PER_MINUTE"] == (
        "${LOGIN_RATE_LIMIT_PER_MINUTE:-60}"
    )
    assert backend_environment["TRUSTED_PROXY_CIDRS"] == "${TRUSTED_PROXY_CIDRS:-}"
    assert backend_environment["SECRET_KEY"].startswith("${SECRET_KEY:?Set SECRET_KEY")
    assert backend_environment["FIRST_SUPERUSER_PASSWORD"].startswith(
        "${FIRST_SUPERUSER_PASSWORD:?Set FIRST_SUPERUSER_PASSWORD"
    )
    assert backend_environment["DEMO_PROVIDER_SNAPSHOT_ENABLED"] == (
        "${DEMO_PROVIDER_SNAPSHOT_ENABLED:-false}"
    )
    assert volumes["app-db-data"]["name"] == "${WORKBENCH_DB_VOLUME:-workbench-db-data}"
    assert volumes["workbench-import-uploads"]["name"] == (
        "${WORKBENCH_IMPORT_UPLOADS_VOLUME:-workbench-import-uploads}"
    )
    assert volumes["workbench-reports"]["name"] == (
        "${WORKBENCH_REPORTS_VOLUME:-workbench-reports}"
    )
    assert volumes["workbench-provider-snapshots"]["name"] == (
        "${WORKBENCH_PROVIDER_SNAPSHOTS_VOLUME:-workbench-provider-snapshots}"
    )
    assert volumes["workbench-provider-cache"]["name"] == (
        "${WORKBENCH_PROVIDER_CACHE_VOLUME:-workbench-provider-cache}"
    )
    assert "template-" not in _as_text(volumes)
    assert "/api/v1/utils/health-check/" in backend_healthcheck
    assert "assert data is True" in backend_healthcheck
    assert "headers={'Host': host}" in backend_healthcheck
    assert legacy_starters == {}


def test_compose_public_app_routes_are_opt_in_and_https_only() -> None:
    compose = yaml.safe_load((REPO_ROOT / "compose.yml").read_text(encoding="utf-8"))
    backend_labels = compose["services"]["backend"]["labels"]
    frontend_labels = compose["services"]["frontend"]["labels"]

    assert "traefik.enable=${TRAEFIK_API_ENABLED:-false}" in backend_labels
    assert "traefik.enable=${TRAEFIK_APP_ENABLED:-false}" in frontend_labels
    assert "TRAEFIK_API_ENABLED=false" in (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    backend_redirect = "traefik.http.routers.workbench-backend-http.middlewares=https-redirect"
    frontend_redirect = "traefik.http.routers.workbench-frontend-http.middlewares=https-redirect"
    assert backend_redirect in backend_labels
    assert frontend_redirect in frontend_labels
    assert "traefik.http.middlewares.https-redirect.redirectscheme.scheme=https" in backend_labels
    assert "traefik.http.middlewares.https-redirect.redirectscheme.permanent=true" in backend_labels
    assert (
        "traefik.http.middlewares.workbench-upload-limit.buffering.maxRequestBodyBytes="
        "${TRAEFIK_MAX_REQUEST_BODY_BYTES:-26214400}"
    ) in backend_labels


def test_traefik_dashboard_route_is_opt_in_and_ip_limited() -> None:
    compose = yaml.safe_load((REPO_ROOT / "compose.traefik.yml").read_text(encoding="utf-8"))
    labels = compose["services"]["traefik"]["labels"]

    assert "traefik.enable=${TRAEFIK_DASHBOARD_ENABLED:-false}" in labels
    assert (
        "traefik.http.middlewares.traefik-dashboard-ipallowlist.ipallowlist.sourcerange="
        "${TRAEFIK_DASHBOARD_IP_ALLOWLIST:-127.0.0.1/32}"
    ) in labels
    assert (
        "traefik.http.routers.traefik-dashboard-https.middlewares=traefik-dashboard-ipallowlist"
    ) in labels


def test_env_example_does_not_pin_api_docs_on_for_shared_deployments() -> None:
    env_example = _read_repo_text(".env.example")

    assert "API_DOCS_ENABLED=true" not in env_example
    assert "\nAPI_DOCS_ENABLED=\n" in env_example
    assert "\nRATE_LIMIT_ENABLED=true\n" in env_example
    assert "\nTRUSTED_PROXY_CIDRS=\n" in env_example
    assert "\nTRAEFIK_APP_ENABLED=false\n" in env_example
    assert "\nMAX_UPLOAD_MB=25\n" in env_example
    assert "\nMAX_REPORT_MB=50\n" in env_example
    assert "\nMAX_REPORTS_PER_RUN=20\n" in env_example
    assert "\nDECISION_API_MAX_FINDINGS=1000\n" in env_example
    assert "\nSECRET_KEY=local-workbench-dev-secret\n" in env_example
    assert "\nFIRST_SUPERUSER_PASSWORD=local-workbench-dev-password\n" in env_example
    assert "\nPOSTGRES_PASSWORD=local-workbench-dev-postgres-password\n" in env_example
    assert "\nWORKBENCH_DB_VOLUME=workbench-db-data\n" in env_example
    assert "\nWORKBENCH_IMPORT_UPLOADS_VOLUME=workbench-import-uploads\n" in env_example
    assert "\nWORKBENCH_REPORTS_VOLUME=workbench-reports\n" in env_example
    assert "\nWORKBENCH_PROVIDER_SNAPSHOTS_VOLUME=workbench-provider-snapshots\n" in env_example
    assert "\nWORKBENCH_PROVIDER_CACHE_VOLUME=workbench-provider-cache\n" in env_example


def test_public_deployment_runbook_documents_backup_retention_and_tls() -> None:
    runbook = _read_repo_text("docs/workbench-public-deployment.md")

    assert "scripts/workbench-backup.sh" in runbook
    assert "scripts/workbench-restore.sh" in runbook
    assert "WORKBENCH_ARTIFACT_MODE=compose" in runbook
    assert "WORKBENCH_IMPORT_UPLOADS_VOLUME=workbench-import-uploads" in runbook
    assert "WORKBENCH_IMPORT_UPLOADS_VOLUME=template-import-uploads" in runbook
    assert "WORKBENCH_LEGACY_STORAGE_FALLBACK=1" in runbook
    assert "POSTGRES_PASSWORD=<long random value>" in runbook
    assert "import-upload, report, provider-snapshot, and\nprovider-cache" in runbook
    assert "/app/template-import-uploads" not in runbook
    assert "python -m app.core.retention --dry-run" in runbook
    assert "TRAEFIK_APP_ENABLED=true" in runbook
    assert "BACKEND_CORS_ORIGINS=https://workbench.example.com" in runbook


def test_backup_restore_scripts_support_database_url_and_compose_artifacts() -> None:
    backup = _read_repo_text("scripts/workbench-backup.sh")
    restore = _read_repo_text("scripts/workbench-restore.sh")

    assert 'pg_dump --format=custom --file="$BACKUP_DIR/workbench.dump" "$DATABASE_URL"' in backup
    assert 'pg_restore --clean --if-exists --dbname="$DATABASE_URL"' in restore
    assert "POSTGRES_PASSWORD must be set in the Compose db container." in backup
    assert "POSTGRES_PASSWORD must be set in the Compose db container." in restore
    assert "WORKBENCH_ARTIFACT_MODE:-host" in backup
    assert "WORKBENCH_ARTIFACT_MODE:-host" in restore
    assert "docker compose ps -q backend" in backup
    assert "docker compose ps -q backend" in restore
    assert "validate_artifact_archive" in restore
    assert "Refusing artifact archive with unsafe member path" in restore
    assert "Refusing artifact archive with symlink or hardlink member" in restore
    assert (
        'DEFAULT_COMPOSE_ARTIFACT_PATHS="workbench-import-uploads workbench-reports '
        'provider-snapshots workbench-provider-cache"' in backup
    )
    assert "LEGACY_COMPOSE_ARTIFACT_PATHS=" in backup
    assert "legacy_storage_fallback_enabled" in backup
    assert "for path in $(host_artifact_paths)" in backup


def test_backup_script_legacy_artifacts_are_opt_in(tmp_path: Path) -> None:
    database_path = tmp_path / "workbench.db"
    database_path.write_text("sqlite bytes\n", encoding="utf-8")
    for artifact_dir in (
        tmp_path / "data" / "workbench-reports",
        tmp_path / "data" / "template-reports",
    ):
        artifact_dir.mkdir(parents=True)
        (artifact_dir / "marker.txt").write_text(artifact_dir.name, encoding="utf-8")

    def run_backup(name: str, *, legacy_fallback: bool = False) -> set[str]:
        backup_dir = tmp_path / name
        env = {
            **os.environ,
            "BACKUP_DIR": str(backup_dir),
            "SQLITE_DATABASE_PATH": str(database_path),
            "WORKBENCH_ARTIFACT_MODE": "host",
        }
        if legacy_fallback:
            env["WORKBENCH_LEGACY_STORAGE_FALLBACK"] = "1"
        subprocess.run(
            [str(REPO_ROOT / "scripts/workbench-backup.sh")],
            capture_output=True,
            check=True,
            cwd=tmp_path,
            env=env,
            text=True,
        )
        with tarfile.open(backup_dir / "artifacts.tar") as archive:
            return set(archive.getnames())

    default_members = run_backup("backup-default")
    legacy_members = run_backup("backup-legacy", legacy_fallback=True)

    assert "workbench-reports" in default_members
    assert "template-reports" not in default_members
    assert "workbench-reports" in legacy_members
    assert "template-reports" in legacy_members


def test_active_runtime_entrypoints_use_workbench_backend_app() -> None:
    dockerfile = (REPO_ROOT / "backend/Dockerfile").read_text(encoding="utf-8")
    override = yaml.safe_load((REPO_ROOT / "compose.override.yml").read_text(encoding="utf-8"))
    playwright_backend = (REPO_ROOT / "scripts/start-workbench-playwright-backend.sh").read_text(
        encoding="utf-8"
    )
    playwright_template = (REPO_ROOT / "scripts/start-template-playwright-backend.sh").read_text(
        encoding="utf-8"
    )

    override_backend_command = _as_text(override["services"]["backend"]["command"])

    assert "alembic -c /app/backend/alembic.ini upgrade head" in dockerfile
    assert "python -m app.core.migration_bootstrap" in dockerfile
    assert "exec uvicorn app.main:app" in dockerfile
    assert "set -e" in override_backend_command
    assert "python -m app.core.migration_bootstrap" in override_backend_command
    assert "alembic -c /app/backend/alembic.ini upgrade head" in override_backend_command
    assert "python3 -m app.core.migration_bootstrap" in playwright_backend
    assert "python3 -m alembic -c backend/alembic.ini upgrade head" in playwright_backend
    assert "frontend-playwright-workbench-$backend_port.db" in playwright_backend
    assert "frontend-playwright-workbench-$backend_port-reports" in playwright_backend
    assert "RATE_LIMIT_ENABLED=false" in playwright_backend
    assert "init_db" not in override_backend_command
    assert "init_db" not in playwright_backend
    assert "app.main:app" in override_backend_command
    assert "uvicorn app.main:app" in playwright_backend
    assert "deprecated" in playwright_template
    assert "start-workbench-playwright-backend.sh" in playwright_template
    for marker in LEGACY_RUNTIME_STARTERS:
        assert marker not in dockerfile
        assert marker not in override_backend_command
        assert marker not in playwright_backend


def test_init_db_does_not_create_schema_metadata() -> None:
    db_source = _read_repo_text("backend/app/core/db.py")
    init_body = db_source.split("def init_db", 1)[1].split(
        "def ensure_configured_superuser",
        1,
    )[0]

    assert "metadata.create_all" not in init_body


def test_generated_browser_api_client_is_built_from_active_backend_app() -> None:
    generate_client = (REPO_ROOT / "scripts/generate-client.sh").read_text(encoding="utf-8")

    assert "from app.main import app" in generate_client
    assert "app.openapi()" in generate_client
    assert "vuln_prioritizer.api" not in generate_client


def test_makefile_has_no_legacy_runtime_smoke_or_compose_path() -> None:
    makefile = _read_repo_text("Makefile")
    docker_demo_smoke = makefile.split("docker-demo-smoke:", 1)[1].split(
        "dependency-audit:",
        1,
    )[0]
    docker_production_smoke = makefile.split("docker-production-smoke:", 1)[1].split(
        "dependency-audit:",
        1,
    )[0]
    playwright_install = makefile.split("playwright-install:", 1)[1].split(
        "playwright-check:",
        1,
    )[0]
    playwright_check = makefile.split("playwright-check:", 1)[1].split("frontend-install:", 1)[0]

    assert "LEGACY_COMPOSE" not in makefile
    assert "docker-postgres-migration-smoke" not in makefile
    assert "api/test_workbench_api.py" not in makefile
    assert "$(BACKEND_TESTS)/playwright" not in makefile
    assert "playwright install --with-deps chromium" in playwright_install
    assert "playwright-check: playwright-install" in makefile
    assert "cd frontend && npm run test" in playwright_check
    assert "tests/ui-smoke.spec.ts tests/responsive-shell.spec.ts" not in playwright_check
    assert "frontend-test-unit-coverage" in makefile
    assert "--profile legacy-postgres" not in docker_demo_smoke
    assert "workbench-postgres" not in docker_demo_smoke
    assert "$(COMPOSE) exec -T backend python -m app.core.schema_smoke" in docker_demo_smoke
    assert (
        "$(PRODUCTION_SMOKE_COMPOSE) exec -T backend python -m app.core.schema_smoke"
        in docker_production_smoke
    )
    assert not any(marker in docker_demo_smoke for marker in LEGACY_RUNTIME_STARTERS)


def test_ci_frontend_gate_runs_coverage_and_full_playwright_suite() -> None:
    workflow = _read_repo_text(".github/workflows/ci.yml")

    assert "make frontend-test-unit-coverage" in workflow
    assert "Run frontend Playwright representative PR gate" not in workflow
    assert "npm --prefix frontend run test -- tests/" not in workflow
    assert "npm --prefix frontend run test" in workflow


def test_cli_does_not_register_removed_workbench_db_or_web_commands() -> None:
    cli_source = _read_repo_text("backend/src/vuln_prioritizer/cli.py")

    assert "commands.db" not in cli_source
    assert "commands.web" not in cli_source
    assert "add_typer(db_app" not in cli_source
    assert "add_typer(web_app" not in cli_source


def test_active_status_contract_has_no_migration_or_legacy_fields() -> None:
    models_source = _read_repo_text("backend/app/models/workbench.py")
    route_source = _read_repo_text("backend/app/api/routes/workbench.py")
    settings_source = _read_repo_text("backend/app/core/config.py")

    combined = "\n".join([models_source, route_source, settings_source])
    assert "MigrationStatus" not in combined
    assert "legacy_api_prefix" not in combined
    assert "legacy_workbench_mounted" not in combined
    assert "LEGACY_API_PREFIX" not in combined


def test_active_runtime_state_uses_workbench_names() -> None:
    app_state_source = _read_repo_text("backend/app/core/app_state.py")
    active_sources = {
        "backend/app/main.py": _read_repo_text("backend/app/main.py"),
        "backend/app/api/deps.py": _read_repo_text("backend/app/api/deps.py"),
        "backend/app/api/routes/login.py": _read_repo_text("backend/app/api/routes/login.py"),
        "backend/app/api/routes/providers.py": _read_repo_text(
            "backend/app/api/routes/providers.py"
        ),
        "backend/app/api/routes/reports.py": _read_repo_text("backend/app/api/routes/reports.py"),
        "backend/app/services/import_execution.py": _read_repo_text(
            "backend/app/services/import_execution.py"
        ),
    }

    assert "WORKBENCH_SETTINGS_STATE_KEY" in app_state_source
    assert "LEGACY_SETTINGS_STATE_KEY" in app_state_source
    assert all('"template_settings"' not in source for source in active_sources.values())
    assert all("template-provider-update" not in source for source in active_sources.values())
    assert all(
        "template-workbench-current-findings" not in source for source in active_sources.values()
    )


def test_runtime_boundary_docs_do_not_advertise_removed_legacy_runtime() -> None:
    docs = "\n".join(
        [
            _read_repo_text("README.md"),
            _read_repo_text("docs/architecture.md"),
            _read_repo_text("docs/submission/technical-documentation.md"),
            _read_repo_text("docs/workbench-threat-model.md"),
            _read_repo_text("docs/user_documentation.md"),
            _read_repo_text("docs/workbench-offline-demo.md"),
            _read_repo_text("docs/support_matrix.md"),
        ]
    )

    assert "`backend/app` is the active browser Workbench runtime." in docs
    assert "compose.legacy.yml" not in docs
    assert "docker-postgres-migration-smoke" not in docs
    assert "vuln-prioritizer web serve" not in docs
    assert "db init" not in docs
    assert "web serve" not in docs
    assert "bootstrap-open" not in docs.lower()
