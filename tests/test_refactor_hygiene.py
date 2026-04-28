from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = ROOT / "src" / "vuln_prioritizer"


def _imported_modules(path: str) -> set[str]:
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def _python_module_paths(*roots: str) -> list[Path]:
    paths: list[Path] = []
    for root in roots:
        paths.extend((SRC_ROOT / root).rglob("*.py"))
    return sorted(paths)


def _module_name(path: Path) -> str:
    relative = path.relative_to(ROOT / "src").with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _normalized_internal_imports(path: Path, known_modules: set[str]) -> set[str]:
    imports: set[str] = set()
    for imported in _imported_modules(str(path.relative_to(ROOT))):
        if not imported.startswith("vuln_prioritizer"):
            continue
        parts = imported.split(".")
        while parts:
            candidate = ".".join(parts)
            if candidate in known_modules:
                imports.add(candidate)
                break
            parts.pop()
    return imports


def test_workbench_web_routes_are_focused_facade_without_api_route_imports() -> None:
    imports = _imported_modules("src/vuln_prioritizer/web/routes.py")

    assert "vuln_prioritizer.api.routes" not in imports
    assert {
        "vuln_prioritizer.web.workbench_governance",
        "vuln_prioritizer.web.workbench_projects",
        "vuln_prioritizer.web.workbench_reports",
        "vuln_prioritizer.web.workbench_settings",
    }.issubset(imports)

    for path in _python_module_paths("web"):
        web_imports = _imported_modules(str(path.relative_to(ROOT)))

        assert "vuln_prioritizer.api.routes" not in web_imports, path


def test_workbench_web_route_facade_preserves_legacy_private_helpers() -> None:
    import vuln_prioritizer.web.routes as web_routes

    expected_names = {
        "_check_csrf",
        "_project_path",
        "_project_nav_context",
        "_safe_project_path_value",
        "_optional_bool_filter",
        "_optional_float_filter",
        "_redacted_database_url",
        "_safe_uuid_path_value",
        "_redacted_env_value",
        "_runtime_config_from_text",
        "_optional_positive_int",
        "_csv_form_values",
        "_asset_audit_snapshot",
        "_validate_detection_attachment_filename",
        "_web_config_diff",
        "_web_collect_config_diff",
        "_selected_import_files",
    }

    assert expected_names.issubset(set(web_routes.__all__))
    assert {name for name in expected_names if not hasattr(web_routes, name)} == set()


def test_workbench_support_does_not_reexport_from_api_routes() -> None:
    imports = _imported_modules("src/vuln_prioritizer/api/workbench_support.py")

    assert "vuln_prioritizer.api.routes" not in imports
    assert {
        "vuln_prioritizer.api.workbench_detection",
        "vuln_prioritizer.api.workbench_findings",
        "vuln_prioritizer.api.workbench_providers",
        "vuln_prioritizer.api.workbench_uploads",
        "vuln_prioritizer.api.workbench_waivers",
    }.issubset(imports)


def test_workbench_job_routes_are_aggregated_from_focused_module() -> None:
    route_imports = _imported_modules("src/vuln_prioritizer/api/routes.py")
    job_route_imports = _imported_modules("src/vuln_prioritizer/api/workbench_jobs.py")
    runner_imports = _imported_modules("src/vuln_prioritizer/services/workbench_job_runner.py")
    routes_source = (ROOT / "src/vuln_prioritizer/api/routes.py").read_text(encoding="utf-8")

    assert "vuln_prioritizer.api.workbench_jobs" in route_imports
    assert '@api_router.get("/jobs"' not in routes_source
    assert '@api_router.post("/jobs' not in routes_source
    assert "vuln_prioritizer.services.workbench_job_runner" in job_route_imports
    assert not {module for module in runner_imports if module.startswith("vuln_prioritizer.api")}


def test_workbench_provider_routes_are_aggregated_from_focused_module() -> None:
    route_imports = _imported_modules("src/vuln_prioritizer/api/routes.py")
    provider_route_imports = _imported_modules(
        "src/vuln_prioritizer/api/workbench_provider_routes.py"
    )
    routes_source = (ROOT / "src/vuln_prioritizer/api/routes.py").read_text(encoding="utf-8")

    assert "vuln_prioritizer.api.workbench_provider_routes" in route_imports
    assert '@api_router.get("/providers/' not in routes_source
    assert '@api_router.post("/providers/' not in routes_source
    assert "vuln_prioritizer.api.workbench_providers" in provider_route_imports
    assert "vuln_prioritizer.services.workbench_jobs" in provider_route_imports


def test_workbench_api_routes_are_domain_router_facade() -> None:
    route_imports = _imported_modules("src/vuln_prioritizer/api/routes.py")
    routes_source = (ROOT / "src/vuln_prioritizer/api/routes.py").read_text(encoding="utf-8")

    assert {
        "vuln_prioritizer.api.workbench_artifact_routes",
        "vuln_prioritizer.api.workbench_attack_detection_routes",
        "vuln_prioritizer.api.workbench_config_routes",
        "vuln_prioritizer.api.workbench_import_routes",
        "vuln_prioritizer.api.workbench_integration_routes",
        "vuln_prioritizer.api.workbench_project_routes",
        "vuln_prioritizer.api.workbench_route_support",
        "vuln_prioritizer.api.workbench_system_routes",
    }.issubset(route_imports)
    assert "@api_router." not in routes_source

    for module in (
        "workbench_artifact_routes",
        "workbench_attack_detection_routes",
        "workbench_config_routes",
        "workbench_import_routes",
        "workbench_integration_routes",
        "workbench_project_routes",
        "workbench_system_routes",
    ):
        source = (SRC_ROOT / "api" / f"{module}.py").read_text(encoding="utf-8")

        assert "router = APIRouter()" in source
        assert "@router." in source
        assert "api_router" not in source


def test_workbench_api_route_facade_preserves_legacy_private_helpers() -> None:
    import vuln_prioritizer.api.routes as api_routes

    expected_names = {
        "_api_token_hash",
        "_artifact_disk_usage",
        "_asset_audit_snapshot",
        "_collect_config_diff",
        "_config_diff_payload",
        "_delete_upload_artifact",
        "_directory_diagnostics",
        "_execute_queued_workbench_job",
        "_job_payload_list",
        "_patched_detection_control_values",
        "_queued_job_analysis_run_id",
        "_queued_job_artifact_path",
        "_queued_job_optional_artifact_path",
        "_resolve_attack_artifact_path",
        "_resolve_provider_snapshot_path",
        "_resolve_upload_artifact",
        "_selected_import_files",
        "_selected_import_formats",
        "_ticket_sync_preview_items",
        "_validate_detection_attachment_filename",
        "_workbench_job_error_message",
    }

    assert expected_names.issubset(set(api_routes.__all__))
    assert {name for name in expected_names if not hasattr(api_routes, name)} == set()
    assert set(inspect.signature(api_routes._execute_queued_workbench_job).parameters) == {
        "repo",
        "session",
        "settings",
        "job",
    }


def test_workbench_job_error_message_is_sanitized() -> None:
    from vuln_prioritizer.api.workbench_jobs import _workbench_job_error_message

    assert _workbench_job_error_message(RuntimeError("secret stack detail")) == (
        "Workbench job execution failed."
    )


def test_workbench_analysis_uses_cli_independent_analysis_service() -> None:
    imports = _imported_modules("src/vuln_prioritizer/services/workbench_analysis.py")

    assert "vuln_prioritizer.cli_support.common" not in imports
    assert "vuln_prioritizer.cli_support.analysis" not in imports
    assert "vuln_prioritizer.cli_options" in imports
    assert "vuln_prioritizer.services.analysis" in imports


def test_core_analysis_service_is_focused_facade() -> None:
    import vuln_prioritizer.services.analysis as service_analysis

    imports = _imported_modules("src/vuln_prioritizer/services/analysis.py")
    source = (ROOT / "src/vuln_prioritizer/services/analysis.py").read_text(encoding="utf-8")
    expected_exports = {
        "AnalysisInputError",
        "AnalysisNoFindingsError",
        "AnalysisRequest",
        "ExplainRequest",
        "ExplainResult",
        "_enum_value",
        "build_active_filters",
        "build_attack_summary_from_findings",
        "build_data_sources",
        "build_findings",
        "build_priority_policy",
        "build_provider_diagnostics",
        "build_provider_freshness",
        "count_epss_hits",
        "count_kev_hits",
        "count_nvd_hits",
        "load_asset_records_or_exit",
        "load_context_profile_or_exit",
        "load_provider_snapshot_or_exit",
        "load_vex_statements_or_exit",
        "load_waiver_rules_or_exit",
        "normalize_priority_filters",
        "prepare_analysis",
        "prepare_explain",
        "prepare_saved_explain",
        "provider_degraded",
        "resolve_attack_options",
        "stale_provider_sources",
        "validate_requested_attack_mode",
    }

    assert {
        "vuln_prioritizer.services.analysis_attack",
        "vuln_prioritizer.services.analysis_filters",
        "vuln_prioritizer.services.analysis_inputs",
        "vuln_prioritizer.services.analysis_models",
        "vuln_prioritizer.services.analysis_pipeline",
        "vuln_prioritizer.services.analysis_provider",
    }.issubset(imports)
    assert "def prepare_analysis" not in source
    assert "class AnalysisRequest" not in source
    assert expected_exports.issubset(set(service_analysis.__all__))
    assert {name for name in expected_exports if not hasattr(service_analysis, name)} == set()

    oversized = {
        str(path.relative_to(ROOT)): len(path.read_text(encoding="utf-8").splitlines())
        for path in _python_module_paths("services")
        if path.name.startswith("analysis_")
        and len(path.read_text(encoding="utf-8").splitlines()) > 800
    }
    assert oversized == {}


def test_service_modules_do_not_import_cli_adapter_modules() -> None:
    for path in _python_module_paths("services"):
        imports = _imported_modules(str(path.relative_to(ROOT)))

        assert not {
            module for module in imports if module.startswith("vuln_prioritizer.cli_support")
        }, path


def test_provider_modules_do_not_import_service_layer_modules() -> None:
    for path in _python_module_paths("providers"):
        imports = _imported_modules(str(path.relative_to(ROOT)))

        assert not {
            module for module in imports if module.startswith("vuln_prioritizer.services")
        }, path


def test_input_loader_uses_focused_parser_package() -> None:
    imports = _imported_modules("src/vuln_prioritizer/inputs/loader.py")
    tree = ast.parse((ROOT / "src/vuln_prioritizer/inputs/loader.py").read_text())
    parse_functions = [
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("parse_")
    ]

    assert "parsers" in imports
    assert parse_functions == []

    parser_modules = _python_module_paths("inputs/parsers")
    assert parser_modules
    oversized = {
        str(path.relative_to(ROOT)): len(path.read_text(encoding="utf-8").splitlines())
        for path in parser_modules
        if len(path.read_text(encoding="utf-8").splitlines()) > 500
    }
    assert oversized == {}


def test_internal_package_import_graph_has_no_module_cycles() -> None:
    paths = _python_module_paths("")
    known_modules = {_module_name(path) for path in paths}
    graph = {
        _module_name(path): _normalized_internal_imports(path, known_modules) for path in paths
    }

    visited: set[str] = set()
    stack: list[str] = []
    in_stack: set[str] = set()

    def visit(module: str) -> None:
        visited.add(module)
        stack.append(module)
        in_stack.add(module)
        for dependency in graph[module]:
            if dependency == module:
                continue
            if dependency not in visited:
                visit(dependency)
            elif dependency in in_stack:
                cycle = stack[stack.index(dependency) :] + [dependency]
                raise AssertionError("Import cycle detected: " + " -> ".join(cycle))
        stack.pop()
        in_stack.remove(module)

    for module in graph:
        if module not in visited:
            visit(module)


def test_focused_workbench_helper_modules_stay_below_size_threshold() -> None:
    checked_paths = [
        *_python_module_paths("api"),
        *_python_module_paths("services"),
        *_python_module_paths("web"),
        SRC_ROOT / "web" / "view_models.py",
    ]
    workbench_helpers = [
        path
        for path in checked_paths
        if path.name.startswith("workbench_") or path.name == "view_models.py"
    ]

    assert workbench_helpers
    oversized = {
        str(path.relative_to(ROOT)): len(path.read_text(encoding="utf-8").splitlines())
        for path in workbench_helpers
        if len(path.read_text(encoding="utf-8").splitlines()) > 800
    }
    assert oversized == {}


def test_reporter_facade_reexports_private_reporting_renderers() -> None:
    imports = _imported_modules("src/vuln_prioritizer/reporter.py")

    assert "vuln_prioritizer.reporting_html" in imports
    assert "vuln_prioritizer.reporting_markdown" in imports
    assert "vuln_prioritizer.reporting_snapshot" in imports
    assert "vuln_prioritizer.reporting_state" in imports


def test_workbench_repository_uses_focused_mixin_boundaries() -> None:
    imports = _imported_modules("src/vuln_prioritizer/db/repositories.py")
    tree = ast.parse((ROOT / "src/vuln_prioritizer/db/repositories.py").read_text())
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    repository = classes["WorkbenchRepository"]
    base_names = {base.id for base in repository.bases if isinstance(base, ast.Name)}

    assert {
        "vuln_prioritizer.db.repository_artifacts",
        "vuln_prioritizer.db.repository_assets",
        "vuln_prioritizer.db.repository_attack",
        "vuln_prioritizer.db.repository_detection",
        "vuln_prioritizer.db.repository_findings",
        "vuln_prioritizer.db.repository_jobs",
        "vuln_prioritizer.db.repository_projects",
        "vuln_prioritizer.db.repository_providers",
        "vuln_prioritizer.db.repository_security",
    }.issubset(imports)
    assert {
        "ArtifactRepositoryMixin",
        "AttackRepositoryMixin",
        "AssetWaiverRepositoryMixin",
        "DetectionControlRepositoryMixin",
        "FindingRepositoryMixin",
        "ProviderSnapshotRepositoryMixin",
        "ProjectRunRepositoryMixin",
        "SecurityAuditRepositoryMixin",
        "WorkbenchJobRepositoryMixin",
    }.issubset(base_names)


def test_reporting_executive_facade_reexports_focused_modules() -> None:
    imports = _imported_modules("src/vuln_prioritizer/reporting_executive.py")

    assert "vuln_prioritizer.reporting_executive_constants" in imports
    assert "vuln_prioritizer.reporting_executive_model" in imports
    assert "vuln_prioritizer.reporting_executive_renderer" in imports


def test_models_facade_reexports_focused_model_modules() -> None:
    imports = _imported_modules("src/vuln_prioritizer/models.py")

    assert "vuln_prioritizer.model_base" in imports
    assert "vuln_prioritizer.models_artifacts" in imports
    assert "vuln_prioritizer.models_attack" in imports
    assert "vuln_prioritizer.models_input" in imports
    assert "vuln_prioritizer.models_provider" in imports
    assert "vuln_prioritizer.models_remediation" in imports
    assert "vuln_prioritizer.models_state" in imports
    assert "vuln_prioritizer.models_waivers" in imports


def test_dependency_audit_requirements_include_dev_gate_tools() -> None:
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    package_names = {line.split(">", 1)[0].split("[", 1)[0] for line in requirements if line}

    assert {"mkdocs", "playwright", "pytest-cov"}.issubset(package_names)


def test_sdist_manifest_excludes_partial_test_tree() -> None:
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")

    assert "prune tests" in manifest


def test_react_workbench_static_entry_is_packaged() -> None:
    index = ROOT / "src" / "vuln_prioritizer" / "web" / "static" / "app" / "index.html"

    assert index.is_file()
    html = index.read_text(encoding="utf-8")
    assert "/static/app/assets/" in html
    assert 'src="/app/assets/' not in html
    assert 'href="/app/assets/' not in html


def test_frontend_preview_uses_fastapi_app_routing() -> None:
    package = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))

    preview = package["scripts"]["preview"]
    assert "vite preview" not in preview
    assert "vuln_prioritizer.cli web serve" in preview
