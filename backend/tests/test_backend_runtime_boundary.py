from __future__ import annotations

import ast
from collections import deque
from pathlib import Path
from typing import Any

import yaml

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
APP_ROOT = BACKEND_ROOT / "app"
SRC_ROOT = BACKEND_ROOT / "src"

LEGACY_RUNTIME_PREFIXES = (
    "vuln_prioritizer.api",
    "vuln_prioritizer.web",
    "vuln_prioritizer.db",
    "vuln_prioritizer.services.workbench_",
    "vuln_prioritizer.provider_scheduler",
    "vuln_prioritizer.workbench_config",
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
    paths = sorted(APP_ROOT.rglob("*.py")) + sorted((SRC_ROOT / "vuln_prioritizer").rglob("*.py"))
    return {_module_name(path): path for path in paths}


def _raw_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
            imports.update(
                f"{node.module}.{alias.name}" for alias in node.names if alias.name != "*"
            )
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


def test_template_backend_import_graph_does_not_reach_legacy_runtime() -> None:
    reachable = _reachable_modules_from_template_backend()

    legacy_runtime_modules = sorted(
        module for module in reachable if _matches_legacy_runtime(module)
    )

    assert legacy_runtime_modules == []


def test_active_compose_services_do_not_start_legacy_workbench_runtime() -> None:
    compose = yaml.safe_load((REPO_ROOT / "compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    default_services = {
        name: service for name, service in services.items() if "profiles" not in service
    }

    default_legacy_starters = {
        name: _as_text(service)
        for name, service in default_services.items()
        if "vuln-prioritizer web serve" in _as_text(service)
        or "vuln_prioritizer.api.app" in _as_text(service)
    }

    assert default_legacy_starters == {}
    assert services["workbench-postgres"]["profiles"] == ["postgres"]
    assert "vuln-prioritizer web serve" in _as_text(services["workbench-postgres"])


def test_active_runtime_entrypoints_use_template_backend_app() -> None:
    dockerfile = (REPO_ROOT / "backend/Dockerfile").read_text(encoding="utf-8")
    override = yaml.safe_load((REPO_ROOT / "compose.override.yml").read_text(encoding="utf-8"))
    playwright_backend = (REPO_ROOT / "scripts/start-template-playwright-backend.sh").read_text(
        encoding="utf-8"
    )

    override_backend_command = _as_text(override["services"]["backend"]["command"])

    assert 'CMD ["uvicorn", "app.main:app"' in dockerfile
    assert "app.main:app" in override_backend_command
    assert "uvicorn app.main:app" in playwright_backend
    assert "vuln_prioritizer.api.app" not in dockerfile
    assert "vuln_prioritizer.api.app" not in override_backend_command
    assert "vuln_prioritizer.api.app" not in playwright_backend


def test_generated_browser_api_client_is_built_from_template_backend_app() -> None:
    generate_client = (REPO_ROOT / "scripts/generate-client.sh").read_text(encoding="utf-8")

    assert "from app.main import app" in generate_client
    assert "app.openapi()" in generate_client
    assert "vuln_prioritizer.api" not in generate_client


def test_template_backend_uses_neutral_token_hashing_helper() -> None:
    app_imports = {
        str(path.relative_to(BACKEND_ROOT)): _raw_imports(path)
        for path in sorted(APP_ROOT.rglob("*.py"))
    }

    legacy_api_security_imports = {
        path: sorted(module for module in imports if module.startswith("vuln_prioritizer.api"))
        for path, imports in app_imports.items()
    }
    legacy_api_security_imports = {
        path: modules for path, modules in legacy_api_security_imports.items() if modules
    }

    assert legacy_api_security_imports == {}
    assert "vuln_prioritizer.security_tokens" in app_imports["app/api/deps.py"]
    assert "vuln_prioritizer.security_tokens" in app_imports["app/api/routes/api_tokens.py"]
