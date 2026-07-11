from __future__ import annotations

import ast
import json
import os
import sqlite3
import subprocess
import sys
import tarfile
import tomllib
from collections import deque
from pathlib import Path
from typing import Any

import yaml

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
APP_ROOT = BACKEND_ROOT / "app"
ENGINE_ROOT = APP_ROOT / "domain" / "engine"

REMOVED_LEGACY_RUNTIME_PATHS = (
    BACKEND_ROOT / "src",
    ENGINE_ROOT / "api",
    ENGINE_ROOT / "web",
    ENGINE_ROOT / "db",
    ENGINE_ROOT / "provider_scheduler.py",
    ENGINE_ROOT / "workbench_config.py",
    ENGINE_ROOT / "commands" / "db.py",
    ENGINE_ROOT / "commands" / "web.py",
    REPO_ROOT / "compose.legacy.yml",
)
LEGACY_RUNTIME_PREFIXES = (
    "app.domain.engine.api",
    "app.domain.engine.web",
    "app.domain.engine.db",
    "app.domain.engine.services.workbench_",
    "app.domain.engine.provider_scheduler",
    "app.domain.engine.workbench_config",
)
LEGACY_RUNTIME_STARTERS = (
    "vuln-prioritizer web serve",
    "app.domain.engine.api.app",
    "app.domain.engine.provider_scheduler",
    "docker-postgres-migration-smoke",
    "compose.legacy.yml",
)


def _module_name(path: Path) -> str:
    if path.is_relative_to(APP_ROOT):
        relative = path.relative_to(BACKEND_ROOT).with_suffix("")
    else:
        relative = path.relative_to(BACKEND_ROOT).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _module_paths() -> dict[str, Path]:
    paths = sorted(APP_ROOT.rglob("*.py"))
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
    if not (imported == "app" or imported.startswith("app.")):
        return None
    parts = imported.split(".")
    while parts:
        candidate = ".".join(parts)
        if candidate in modules:
            return candidate
        parts.pop()
    return None


def _reachable_modules_from_workbench_backend() -> set[str]:
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


def _read_repo_toml(path: str) -> dict[str, Any]:
    with (REPO_ROOT / path).open("rb") as handle:
        return tomllib.load(handle)


def test_legacy_workbench_runtime_source_is_removed() -> None:
    remaining_paths = [path for path in REMOVED_LEGACY_RUNTIME_PATHS if path.exists()]
    remaining_workbench_services = sorted(ENGINE_ROOT.glob("services/workbench_*.py"))

    assert remaining_paths == []
    assert remaining_workbench_services == []


def test_workbench_backend_import_graph_does_not_reach_legacy_runtime() -> None:
    reachable = _reachable_modules_from_workbench_backend()

    legacy_runtime_modules = sorted(
        module for module in reachable if _matches_legacy_runtime(module)
    )

    assert legacy_runtime_modules == []


def test_workbench_runtime_names_are_not_active_service_aliases() -> None:
    analysis_service = _read_repo_text("backend/app/services/analysis.py")
    import_artifacts = _read_repo_text("backend/app/services/import_artifacts.py")
    provider_updates = _read_repo_text("backend/app/services/provider_updates.py")
    app_state = _read_repo_text("backend/app/core/app_state.py")
    public_deployment = _read_repo_text("docs/workbench-public-deployment.md")
    frontend_defaults = _read_repo_text("frontend/src/lib/app-defaults.ts")

    assert "class WorkbenchAnalysisError" in analysis_service
    assert "class WorkbenchAnalysisResult" in analysis_service
    assert "DEFAULT_WORKBENCH_PROVIDER_SNAPSHOT" in analysis_service
    assert "TemplateAnalysisError" not in analysis_service
    assert "TemplateAnalysisResult" not in analysis_service
    assert "DEFAULT_TEMPLATE_PROVIDER_SNAPSHOT" not in analysis_service

    assert "resolve_template_provider_snapshot_path" not in import_artifacts
    assert "resolve_template_attack_artifact_path" not in import_artifacts
    assert "TemplateProviderUpdateConflict" not in provider_updates
    assert "TemplateProviderUpdateValidationError" not in provider_updates

    assert 'WORKBENCH_SETTINGS_STATE_KEY = "workbench_settings"' in app_state
    assert '"template_settings"' not in app_state
    normalized_public_deployment = " ".join(public_deployment.split())
    assert "template_settings" not in normalized_public_deployment
    assert "WORKBENCH_LEGACY_STORAGE_FALLBACK" not in normalized_public_deployment
    assert "ReportFormatCapabilityPublic" not in frontend_defaults
    assert "WorkbenchReportFormat" not in frontend_defaults
    assert "TemplateReportFormat" not in frontend_defaults

    active_runtime_docs = [
        _read_repo_text("backend/app/__init__.py"),
        _read_repo_text("backend/app/api/routes/__init__.py"),
        _read_repo_text("backend/app/core/local_actor.py"),
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


def test_container_image_digest_policy_covers_compose_service_images() -> None:
    digest_check = _read_repo_text("scripts/check_dockerfile_base_digests.py")
    makefile = _read_repo_text("Makefile")
    dockerignore = _read_repo_text(".dockerignore")
    compose = yaml.safe_load(_read_repo_text("compose.yml"))
    traefik_compose = yaml.safe_load(_read_repo_text("compose.traefik.yml"))

    assert "compose.yml" in digest_check
    assert "compose.traefik.yml" in digest_check
    assert "Dockerfile.playwright" in digest_check
    assert "MAKE_IMAGE_RE" in digest_check
    assert "services" in digest_check
    assert ".env" in dockerignore
    assert "!.env.example" in dockerignore
    assert "ACTIONLINT_IMAGE ?= rhysd/actionlint:1.7.12@sha256:" in makefile
    assert "audit --audit-level=high" in makefile
    assert "@sha256:" in compose["services"]["db"]["image"]
    assert "@sha256:" in traefik_compose["services"]["traefik"]["image"]


def test_runtime_containers_keep_upgrade_and_package_surface_guards() -> None:
    backend_dockerfile = _read_repo_text("backend/Dockerfile")
    frontend_dockerfile = _read_repo_text("frontend/Dockerfile")

    assert "python -m pip install --upgrade pip" not in backend_dockerfile
    assert "python -m pip install --require-hashes" in backend_dockerfile
    assert "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends" in (
        backend_dockerfile
    )
    assert "python -m pip uninstall -y pip setuptools wheel" in backend_dockerfile
    assert "apk upgrade --no-cache" in frontend_dockerfile
    assert "apk del --no-network curl libcurl nginx-module-image-filter" in frontend_dockerfile
    assert "npm ci --workspaces=false --engine-strict=true" in frontend_dockerfile
    assert "npm --workspaces=false --engine-strict=true run build" in frontend_dockerfile


def test_node_package_manifests_pin_ci_runtime_family() -> None:
    expected_engines = {"node": ">=22 <23", "npm": ">=10.9 <11"}
    packages = [
        json.loads(_read_repo_text("package.json")),
        json.loads(_read_repo_text("frontend/package.json")),
    ]

    for package in packages:
        assert package["packageManager"] == "npm@10.9.4"
        assert package["engines"] == expected_engines


def test_github_workflow_actions_are_sha_pinned() -> None:
    makefile = _read_repo_text("Makefile")
    pin_check = _read_repo_text("scripts/check_github_action_pins.py")

    assert "scripts/check_github_action_pins.py" in makefile
    assert "GitHub workflow remote actions must be pinned by commit SHA" in pin_check
    assert "GitHub checkout steps must disable persisted credentials" in pin_check

    result = subprocess.run(
        ["python3", "scripts/check_github_action_pins.py"],
        capture_output=True,
        cwd=REPO_ROOT,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_github_workflow_checkouts_do_not_persist_credentials() -> None:
    offenders: list[str] = []

    for workflow in sorted((REPO_ROOT / ".github" / "workflows").glob("*.y*ml")):
        document = yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}
        jobs = document.get("jobs", {})
        if not isinstance(jobs, dict):
            continue
        for job_name, job in sorted(jobs.items()):
            if not isinstance(job, dict):
                continue
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue
            for index, step in enumerate(steps, 1):
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses")
                if not isinstance(uses, str) or not uses.startswith("actions/checkout@"):
                    continue
                with_config = step.get("with")
                if (
                    not isinstance(with_config, dict)
                    or with_config.get("persist-credentials") is not False
                ):
                    offenders.append(f"{workflow.relative_to(REPO_ROOT)}:{job_name}:step-{index}")

    assert offenders == []


def test_codeql_installs_python_dependencies_only_for_python_analysis() -> None:
    workflow = _read_repo_text(".github/workflows/codeql.yml")

    assert "Decide whether CodeQL analysis is needed" in workflow
    assert "run-codeql=$1" in workflow
    assert "write_codeql_output false" in workflow
    assert "No CodeQL-relevant source or dependency inputs changed" in workflow
    assert "fetch-depth: 0" in workflow
    assert "matrix.language == 'python'" in workflow
    assert "steps.codeql-scope.outputs.run-codeql == 'true' && matrix.language == 'python'" in (
        workflow
    )
    assert 'python -m pip install -e "backend[dev]"' in workflow
    assert "language: javascript-typescript" in workflow


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
    assert backend_environment["MAX_REQUEST_BODY_MB"] == "${MAX_REQUEST_BODY_MB:-2}"
    assert backend_environment["MAX_REPORT_MB"] == "${MAX_REPORT_MB:-50}"
    assert backend_environment["MAX_REPORTS_PER_RUN"] == "${MAX_REPORTS_PER_RUN:-20}"
    assert backend_environment["DECISION_API_MAX_FINDINGS"] == (
        "${DECISION_API_MAX_FINDINGS:-1000}"
    )
    assert backend_environment["COMPOSE_COMPATIBILITY_MODE"] == "true"
    assert backend_environment["POSTGRES_PASSWORD"].startswith(
        "${POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD"
    )
    assert "LOGIN_RATE_LIMIT_PER_MINUTE" not in backend_environment
    assert "TOKEN_FAILURE_RATE_LIMIT_PER_MINUTE" not in backend_environment
    assert "API_TOKEN_DEFAULT_EXPIRE_DAYS" not in backend_environment
    assert "SESSION_RETENTION_DAYS" not in backend_environment
    assert "REVOKED_API_TOKEN_RETENTION_DAYS" not in backend_environment
    assert backend_environment["TRUSTED_PROXY_CIDRS"] == "${TRUSTED_PROXY_CIDRS:-}"
    assert backend_environment["SECRET_KEY"].startswith("${SECRET_KEY:?Set SECRET_KEY")
    assert backend_environment["LOCAL_WORKBENCH_USER_EMAIL"] == (
        "${LOCAL_WORKBENCH_USER_EMAIL:-local@workbench.test}"
    )
    assert "FIRST_SUPERUSER" not in backend_environment
    assert "FIRST_SUPERUSER_PASSWORD" not in backend_environment
    assert backend_environment["DEMO_PROVIDER_SNAPSHOT_ENABLED"] == (
        "${DEMO_PROVIDER_SNAPSHOT_ENABLED:-false}"
    )
    assert backend_environment["DEMO_WORKSPACE_ENABLED"] == ("${DEMO_WORKSPACE_ENABLED:-false}")
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
        "traefik.http.routers.workbench-backend-https.middlewares="
        "workbench-api-ipallowlist,workbench-upload-limit"
    ) in backend_labels
    assert (
        "traefik.http.middlewares.workbench-api-ipallowlist.ipallowlist.sourcerange="
        "${TRAEFIK_API_IP_ALLOWLIST:-127.0.0.1/32}"
    ) in backend_labels
    assert (
        "traefik.http.routers.workbench-frontend-https.middlewares=workbench-app-ipallowlist"
    ) in frontend_labels
    assert (
        "traefik.http.middlewares.workbench-app-ipallowlist.ipallowlist.sourcerange="
        "${TRAEFIK_APP_IP_ALLOWLIST:-127.0.0.1/32}"
    ) in frontend_labels
    assert (
        "traefik.http.middlewares.workbench-upload-limit.buffering.maxRequestBodyBytes="
        "${TRAEFIK_MAX_REQUEST_BODY_BYTES:-26214400}"
    ) in backend_labels


def test_traefik_dashboard_route_is_opt_in_ip_limited_and_basic_auth_protected() -> None:
    compose = yaml.safe_load((REPO_ROOT / "compose.traefik.yml").read_text(encoding="utf-8"))
    traefik = compose["services"]["traefik"]
    labels = traefik["labels"]
    env_example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")

    assert traefik["read_only"] is True
    assert traefik["cap_drop"] == ["ALL"]
    assert traefik["cap_add"] == ["NET_BIND_SERVICE"]
    assert traefik["security_opt"] == ["no-new-privileges:true"]
    assert "/tmp" in traefik["tmpfs"]
    assert "traefik.enable=${TRAEFIK_DASHBOARD_ENABLED:-false}" in labels
    assert (
        "traefik.http.middlewares.traefik-dashboard-ipallowlist.ipallowlist.sourcerange="
        "${TRAEFIK_DASHBOARD_IP_ALLOWLIST:-127.0.0.1/32}"
    ) in labels
    assert (
        "traefik.http.middlewares.traefik-dashboard-auth.basicauth.users="
        "${TRAEFIK_DASHBOARD_AUTH_USERS:-dashboard-disabled:"
    ) in "\n".join(labels)
    assert (
        "traefik.http.routers.traefik-dashboard-https.middlewares="
        "traefik-dashboard-ipallowlist,traefik-dashboard-auth"
    ) in labels
    assert "TRAEFIK_DASHBOARD_AUTH_USERS=" in env_example
    assert "openssl passwd -apr1" in env_example


def test_env_example_does_not_pin_api_docs_on_for_shared_deployments() -> None:
    env_example = _read_repo_text(".env.example")

    assert "API_DOCS_ENABLED=true" not in env_example
    assert "\nAPI_DOCS_ENABLED=\n" in env_example
    assert "\nRATE_LIMIT_ENABLED=true\n" in env_example
    assert "\nTRUSTED_PROXY_CIDRS=\n" in env_example
    assert "\nTRAEFIK_APP_ENABLED=false\n" in env_example
    assert "\nTRAEFIK_APP_IP_ALLOWLIST=127.0.0.1/32\n" in env_example
    assert "\nTRAEFIK_API_IP_ALLOWLIST=127.0.0.1/32\n" in env_example
    assert "\nMAX_UPLOAD_MB=25\n" in env_example
    assert "\nMAX_REQUEST_BODY_MB=2\n" in env_example
    assert "\nMAX_REPORT_MB=50\n" in env_example
    assert "\nMAX_REPORTS_PER_RUN=20\n" in env_example
    assert "\nDECISION_API_MAX_FINDINGS=1000\n" in env_example
    assert "\nSECRET_KEY=local-workbench-dev-secret\n" in env_example
    assert "\nLOCAL_WORKBENCH_USER_EMAIL=local@workbench.test\n" in env_example
    assert "\nDEMO_WORKSPACE_ENABLED=false\n" in env_example
    assert "FIRST_SUPERUSER=" not in env_example
    assert "FIRST_SUPERUSER_PASSWORD" not in env_example
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
    assert "POSTGRES_PASSWORD=<long random value>" in runbook
    assert "import-upload, report, provider-snapshot, and\nprovider-cache" in runbook
    assert "/app/template-import-uploads" not in runbook
    assert "python -m app.core.retention --dry-run" in runbook
    assert "TRAEFIK_APP_ENABLED=true" in runbook
    assert "TRAEFIK_APP_IP_ALLOWLIST=<operator-or-private-network-cidr>" in runbook
    assert "TRAEFIK_API_IP_ALLOWLIST=<automation-source-cidr>" in runbook
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
    assert "sqlite_backup.py" in backup
    assert "sqlite_backup.py" in restore
    assert "Refusing artifact archive with unsafe member path" in restore
    assert "Refusing artifact archive with symlink or hardlink member" in restore
    assert (
        'DEFAULT_COMPOSE_ARTIFACT_PATHS="workbench-import-uploads workbench-reports '
        'provider-snapshots workbench-provider-cache"' in backup
    )
    assert "LEGACY_COMPOSE_ARTIFACT_PATHS=" not in backup
    assert "legacy_storage_fallback_enabled" not in backup
    assert "host_artifact_paths | while IFS= read -r path" in backup


def test_backup_script_uses_workbench_artifacts_only_by_default(tmp_path: Path) -> None:
    database_path = tmp_path / "workbench.db"
    database = sqlite3.connect(database_path)
    database.execute("PRAGMA journal_mode=WAL")
    database.execute("CREATE TABLE backup_probe (value TEXT NOT NULL)")
    database.execute("INSERT INTO backup_probe (value) VALUES ('committed-in-wal')")
    database.commit()
    for artifact_dir in (tmp_path / "reports", tmp_path / "template-reports"):
        artifact_dir.mkdir(parents=True)
        (artifact_dir / "marker.txt").write_text(artifact_dir.name, encoding="utf-8")

    def run_backup(name: str) -> set[str]:
        backup_dir = tmp_path / name
        env = {
            **os.environ,
            "BACKUP_DIR": str(backup_dir),
            "SQLITE_DATABASE_PATH": str(database_path),
            "WORKBENCH_ARTIFACT_MODE": "host",
        }
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

    try:
        default_members = run_backup("backup-default")
    finally:
        database.close()

    assert "reports" in default_members
    assert "template-reports" not in default_members
    restored = sqlite3.connect(tmp_path / "backup-default" / "workbench.db")
    try:
        assert restored.execute("SELECT value FROM backup_probe").fetchone() == (
            "committed-in-wal",
        )
    finally:
        restored.close()


def test_sqlite_restore_is_verified_and_refuses_active_wal_destination(tmp_path: Path) -> None:
    backup = tmp_path / "backup.db"
    database = sqlite3.connect(backup)
    try:
        database.execute("CREATE TABLE restore_probe (value TEXT NOT NULL)")
        database.execute("INSERT INTO restore_probe (value) VALUES ('verified-restore')")
        database.commit()
    finally:
        database.close()

    destination = tmp_path / "runtime" / "workbench.db"
    destination.parent.mkdir()
    database = sqlite3.connect(destination)
    try:
        database.execute("CREATE TABLE old_probe (value TEXT NOT NULL)")
        database.commit()
    finally:
        database.close()
    sidecar = destination.with_name(f"{destination.name}-wal")
    sidecar.write_bytes(b"active-or-uncheckpointed")
    command = [
        sys.executable,
        str(REPO_ROOT / "scripts/sqlite_backup.py"),
        "restore",
        str(backup),
        str(destination),
    ]

    refused = subprocess.run(command, capture_output=True, check=False, text=True)

    assert refused.returncode != 0
    assert "WAL sidecars" in refused.stderr
    database = sqlite3.connect(destination)
    try:
        assert database.execute("SELECT name FROM sqlite_master WHERE name='old_probe'").fetchone()
    finally:
        database.close()

    for suffix in ("-wal", "-shm"):
        destination.with_name(f"{destination.name}{suffix}").unlink(missing_ok=True)
    subprocess.run(command, capture_output=True, check=True, text=True)
    database = sqlite3.connect(destination)
    try:
        assert database.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert database.execute("SELECT value FROM restore_probe").fetchone() == (
            "verified-restore",
        )
    finally:
        database.close()


def test_restore_validates_artifact_archive_before_replacing_sqlite(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    database = sqlite3.connect(backup_dir / "workbench.db")
    try:
        database.execute("CREATE TABLE replacement_probe (value TEXT NOT NULL)")
        database.commit()
    finally:
        database.close()
    with tarfile.open(backup_dir / "artifacts.tar", "w") as archive:
        member = tarfile.TarInfo("../escaped.txt")
        member.size = 0
        archive.addfile(member)
    destination = tmp_path / "runtime" / "workbench.db"
    destination.parent.mkdir()
    database = sqlite3.connect(destination)
    try:
        database.execute("CREATE TABLE preserved_probe (value TEXT NOT NULL)")
        database.commit()
    finally:
        database.close()

    restored = subprocess.run(
        [str(REPO_ROOT / "scripts/workbench-restore.sh"), str(backup_dir)],
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "SQLITE_DATABASE_PATH": str(destination),
            "ARTIFACT_RESTORE_ROOT": str(destination.parent),
        },
        text=True,
    )

    assert restored.returncode != 0
    assert "unsafe member path" in restored.stderr
    database = sqlite3.connect(destination)
    try:
        assert database.execute(
            "SELECT name FROM sqlite_master WHERE name='preserved_probe'"
        ).fetchone()
    finally:
        database.close()
    assert not (tmp_path / "escaped.txt").exists()


def test_active_runtime_entrypoints_use_workbench_backend_app() -> None:
    dockerfile = (REPO_ROOT / "backend/Dockerfile").read_text(encoding="utf-8")
    override = yaml.safe_load((REPO_ROOT / "compose.override.yml").read_text(encoding="utf-8"))
    playwright_backend = (REPO_ROOT / "scripts/start-workbench-playwright-backend.sh").read_text(
        encoding="utf-8"
    )

    override_backend_command = _as_text(override["services"]["backend"]["command"])

    assert "alembic -c /app/backend/alembic.ini upgrade head" in dockerfile
    assert "python -m app.core.migration_bootstrap" not in dockerfile
    assert "exec uvicorn app.main:app" in dockerfile
    assert "set -e" in override_backend_command
    assert "python -m app.core.migration_bootstrap" not in override_backend_command
    assert "alembic -c /app/backend/alembic.ini upgrade head" in override_backend_command
    assert "python3 -m app.core.migration_bootstrap" not in playwright_backend
    assert "python3 -m alembic -c backend/alembic.ini upgrade head" in playwright_backend
    assert "frontend-playwright-workbench-$backend_port.db" in playwright_backend
    assert "frontend-playwright-workbench-$backend_port-reports" in playwright_backend
    assert "RATE_LIMIT_ENABLED=false" in playwright_backend
    assert "init_db" not in override_backend_command
    assert "init_db" not in playwright_backend
    assert "app.main:app" in override_backend_command
    assert "uvicorn app.main:app" in playwright_backend
    for marker in LEGACY_RUNTIME_STARTERS:
        assert marker not in dockerfile
        assert marker not in override_backend_command
        assert marker not in playwright_backend


def test_init_db_does_not_create_schema_metadata() -> None:
    db_source = _read_repo_text("backend/app/core/db.py")
    init_body = db_source.split("def init_db", 1)[1]

    assert "metadata.create_all" not in init_body
    assert "ensure_configured_superuser" not in db_source


def test_generated_browser_api_client_is_built_from_active_backend_app() -> None:
    generate_client = (REPO_ROOT / "scripts/generate-client.sh").read_text(encoding="utf-8")

    assert "from app.main import app" in generate_client
    assert "app.openapi()" in generate_client
    assert "app.domain.engine.api" not in generate_client


def test_makefile_has_no_legacy_runtime_smoke_or_compose_path() -> None:
    makefile = _read_repo_text("Makefile")
    release_readiness = makefile.split("release-readiness-check:", 1)[1].split(
        "precommit-install:",
        1,
    )[0]
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
    assert "playwright-check-without-design-audit: playwright-install" in makefile
    assert "$(FRONTEND_NPM) run test" in playwright_check
    assert (
        '--grep-invert "design audit matches VPW visual regression baselines"' in playwright_check
    )
    assert "tests/ui-smoke.spec.ts tests/responsive-shell.spec.ts" not in playwright_check
    assert "frontend-test-unit-coverage" in makefile
    assert "public-production-evidence-check" not in release_readiness
    assert "release-check api-client-drift-check archive-evidence-check" in release_readiness
    assert (
        "frontend-design-audit-linux-docker playwright-check-without-design-audit"
        in release_readiness
    )
    assert "--profile legacy-postgres" not in docker_demo_smoke
    assert "workbench-postgres" not in docker_demo_smoke
    assert "$(COMPOSE) up -d --build backend frontend worker" in docker_demo_smoke
    assert (
        "$(PRODUCTION_SMOKE_COMPOSE) up -d --build backend frontend worker"
        in docker_production_smoke
    )
    assert "$(COMPOSE) exec -T backend python -m app.core.schema_smoke" in docker_demo_smoke
    assert (
        "$(PRODUCTION_SMOKE_COMPOSE) exec -T backend python -m app.core.schema_smoke"
        in docker_production_smoke
    )
    assert not any(marker in docker_demo_smoke for marker in LEGACY_RUNTIME_STARTERS)


def test_ci_frontend_gate_tiers_playwright_and_visual_audit_by_change_scope() -> None:
    workflow = _read_repo_text(".github/workflows/ci.yml")

    assert "make frontend-test-unit-coverage" in workflow
    assert "Run frontend Playwright representative PR gate" not in workflow
    assert (
        "npm --prefix frontend --workspaces=false --engine-strict=true run test -- tests/"
        not in workflow
    )
    assert (
        "scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true run test"
    ) in workflow
    assert "write_frontend_outputs()" in workflow
    assert 'write_frontend_outputs true true true "chromium firefox webkit" ""' in workflow
    assert (
        "write_frontend_outputs false false false chromium "
        '"--project=chromium --project=mobile-chromium"'
    ) in workflow
    assert "run-browser=$2" in workflow
    assert "playwright-browsers=$4" in workflow
    assert "playwright-projects=$5" in workflow
    assert "steps.frontend-scope.outputs.run-browser == 'true'" in workflow
    assert "Skip frontend browser gate" in workflow
    assert "steps.frontend-scope.outputs.run-design-audit == 'true'" in workflow
    assert "frontend/src/main.tsx|frontend/src/index.css|frontend/src/styles/*" in workflow
    assert "frontend/src/*" in workflow
    assert "backend/app/api/*|backend/app/main.py|backend/app/core/config.py" in workflow
    assert "frontend/*|backend/app/*" in workflow
    assert ".nvmrc|.npmrc|package.json" in workflow


def test_ci_docker_gate_tiers_demo_full_and_image_security_work() -> None:
    workflow = _read_repo_text(".github/workflows/docker.yml")

    assert 'cron: "43 4 * * 2"' in workflow
    assert ".nvmrc|.npmrc|package.json|frontend/package.json|frontend/package-lock.json" in workflow
    assert "docker-smoke-mode: ${{ steps.scope.outputs.docker-smoke-mode }}" in workflow
    assert "run-image-security: ${{ steps.scope.outputs.run-image-security }}" in workflow
    assert "write_docker_outputs()" in workflow
    assert "write_docker_outputs true full true" in workflow
    assert 'write_docker_outputs true "$docker_smoke_mode" "$image_security_output"' in workflow
    assert "set_demo_smoke()" in workflow
    assert "set_full_smoke()" in workflow
    assert "docker_smoke_mode=demo" in workflow
    assert "image_security_output=true" in workflow
    assert "make docker-demo-smoke" in workflow
    assert "make docker-production-smoke" in workflow
    assert "needs.changes.outputs.docker-smoke-mode == 'full'" in workflow
    assert "needs.changes.outputs.run-image-security == 'true'" in workflow


def test_ci_cost_report_workflow_tracks_runner_minutes_without_write_tokens() -> None:
    workflow = _read_repo_text(".github/workflows/ci-cost-report.yml")
    script = _read_repo_text("scripts/ci_cost_report.py")
    makefile = _read_repo_text("Makefile")

    assert "name: CI Cost Report" in workflow
    assert 'cron: "23 5 * * 1"' in workflow
    assert "actions: read" in workflow
    assert "contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert "python3 scripts/ci_cost_report.py" in workflow
    assert "--json-output build/ci-cost/ci-cost-report.json" in workflow
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in workflow
    assert 'DEFAULT_WORKFLOWS = ("CI", "Docker", "CodeQL")' in script
    assert "total_job_minutes" in script
    assert "ci-cost-report:" in makefile


def test_legacy_cli_entrypoint_is_removed() -> None:
    assert not (REPO_ROOT / "backend/src").exists()


def test_backend_package_boundary_matches_pytest_coverage_boundary() -> None:
    backend_pyproject = _read_repo_toml("backend/pyproject.toml")
    root_pyproject = _read_repo_toml("pyproject.toml")

    package_include = set(backend_pyproject["tool"]["setuptools"]["packages"]["find"]["include"])
    assert package_include == {"app*"}

    for config, expected_pythonpath in (
        (backend_pyproject, {"."}),
        (root_pyproject, {"backend"}),
    ):
        pytest_options = config["tool"]["pytest"]["ini_options"]
        addopts = set(pytest_options["addopts"].split())
        assert {"--cov=app"}.issubset(addopts)
        assert "--cov=vuln_prioritizer" not in addopts
        assert not any(option.startswith("--cov-fail-under") for option in addopts)
        assert set(pytest_options["pythonpath"]) == expected_pythonpath

    makefile = _read_repo_text("Makefile")
    assert "$(PYTHON) -m coverage json -o build/coverage-current.json" in makefile
    assert "$(MAKE) critical-coverage-check" in makefile
    assert "$(PYTHON) scripts/check_critical_coverage.py build/coverage-current.json" in makefile


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
        "backend/app/api/routes/providers.py": _read_repo_text(
            "backend/app/api/routes/providers.py"
        ),
        "backend/app/api/routes/reports.py": _read_repo_text("backend/app/api/routes/reports.py"),
        "backend/app/services/import_execution.py": _read_repo_text(
            "backend/app/services/import_execution.py"
        ),
    }

    assert "WORKBENCH_SETTINGS_STATE_KEY" in app_state_source
    assert "LEGACY_SETTINGS_STATE_KEY" not in app_state_source
    assert all('"template_settings"' not in source for source in active_sources.values())
    assert all("template-provider-update" not in source for source in active_sources.values())
    assert all(
        "template-workbench-current-findings" not in source for source in active_sources.values()
    )
    assert not (REPO_ROOT / "backend/app/api/routes/login.py").exists()
    assert not (REPO_ROOT / "backend/app/api/routes/api_tokens.py").exists()
    assert not (REPO_ROOT / "backend/app/api/routes/users.py").exists()


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
