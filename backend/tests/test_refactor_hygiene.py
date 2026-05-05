from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent
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


def test_template_backend_does_not_import_legacy_workbench_layers() -> None:
    backend_app_root = ROOT / "app"
    blocked_prefixes = (
        "vuln_prioritizer.api",
        "vuln_prioritizer.db",
        "vuln_prioritizer.web",
        "vuln_prioritizer.services.workbench_",
    )

    violations = {
        str(path.relative_to(ROOT)): sorted(
            module
            for module in _imported_modules(str(path.relative_to(ROOT)))
            if module.startswith(blocked_prefixes)
        )
        for path in sorted(backend_app_root.rglob("*.py"))
    }
    violations = {path: modules for path, modules in violations.items() if modules}

    assert violations == {}


def test_legacy_workbench_runtime_modules_are_removed() -> None:
    removed_paths = [
        SRC_ROOT / "api",
        SRC_ROOT / "web",
        SRC_ROOT / "db",
        SRC_ROOT / "provider_scheduler.py",
        SRC_ROOT / "workbench_config.py",
        SRC_ROOT / "commands" / "db.py",
        SRC_ROOT / "commands" / "web.py",
    ]

    assert [path for path in removed_paths if path.exists()] == []
    assert sorted(SRC_ROOT.glob("services/workbench_*.py")) == []


def test_template_report_contracts_are_split_from_renderer_facade() -> None:
    imports = _imported_modules("app/services/reports.py")
    source = (ROOT / "app/services/reports.py").read_text(encoding="utf-8")
    contracts_source = (ROOT / "app/services/report_contracts.py").read_text(encoding="utf-8")
    models_source = (ROOT / "app/services/report_models.py").read_text(encoding="utf-8")
    renderers_source = (ROOT / "app/services/report_renderers.py").read_text(encoding="utf-8")

    assert "app.services.report_contracts" in imports
    assert "app.services.report_models" in imports
    assert "app.services.report_renderers" in imports
    assert "CSV_FINDINGS_COLUMNS = [" not in source
    assert "EXECUTIVE_REPORT_CSS = " not in source
    assert "def render_markdown_report" not in source
    assert "def render_evidence_bundle_zip" not in source
    assert "class MarkdownReportPayload" not in source
    assert "CSV_FINDINGS_COLUMNS = [" in contracts_source
    assert "REPORT_FILENAME_EVIDENCE_BUNDLE" in contracts_source
    assert "class MarkdownReportPayload" in models_source
    assert "EXECUTIVE_REPORT_CSS = " in renderers_source
    assert "def render_evidence_bundle_zip" in renderers_source


def test_template_import_validation_and_storage_are_split_from_route_facade() -> None:
    imports = _imported_modules("app/api/routes/imports.py")
    source = (ROOT / "app/api/routes/imports.py").read_text(encoding="utf-8")
    upload_source = (ROOT / "app/services/import_uploads.py").read_text(encoding="utf-8")
    artifact_source = (ROOT / "app/services/import_artifacts.py").read_text(encoding="utf-8")

    assert "app.services.import_uploads" in imports
    assert "app.services.import_artifacts" in imports
    assert "ALLOWED_UPLOAD_SUFFIXES = " not in source
    assert "def _read_bounded_upload" not in source
    assert "def _store_upload" not in source
    assert "def _resolve_template_provider_snapshot_path" not in source
    assert "ALLOWED_UPLOAD_SUFFIXES = " in upload_source
    assert "def store_upload" in upload_source
    assert "def resolve_template_provider_snapshot_path" in artifact_source
    assert "def validate_attack_import_options" in artifact_source


def test_frontend_routes_use_workbench_route_containers_instead_of_app_facade() -> None:
    route_files = sorted((REPO_ROOT / "frontend/src/routes/_layout").glob("*.tsx"))
    active_route_files = [path for path in route_files if path.name != "assets.tsx"]
    app_facade = REPO_ROOT / "frontend/src/App.tsx"

    assert not app_facade.exists()
    assert active_route_files
    for path in active_route_files:
        source = path.read_text(encoding="utf-8")

        assert "../../App" not in source, path
        assert "workbench/routes/" in source, path


def test_workbench_route_containers_use_explicit_shell_routes() -> None:
    route_files = sorted((REPO_ROOT / "frontend/src/workbench/routes").glob("*Route.tsx"))

    assert route_files
    for path in route_files:
        source = path.read_text(encoding="utf-8")

        assert "WorkbenchRouteApp" not in source, path
        assert "WorkbenchShell" in source, path
        assert "routePath=" in source, path

    findings_route = (REPO_ROOT / "frontend/src/workbench/routes/FindingsRoute.tsx").read_text(
        encoding="utf-8"
    )
    finding_detail_route = (
        REPO_ROOT / "frontend/src/workbench/routes/FindingDetailRoute.tsx"
    ).read_text(encoding="utf-8")
    assert "Outlet" in findings_route
    assert "findingDetailId=" not in findings_route
    assert "findingDetailId=" in finding_detail_route


def test_workbench_shell_lazy_loads_heavy_product_surfaces() -> None:
    source = (REPO_ROOT / "frontend/src/workbench/WorkbenchShell.tsx").read_text(encoding="utf-8")

    assert "lazy(() =>" in source
    assert 'import("../components/findings/RemediationQueue")' in source
    assert 'import("../components/dashboard/RiskOperationsDashboard")' in source
    assert 'import("../components/reports/EvidenceCenter")' in source
    assert 'from "../components/findings"' not in source
    assert 'from "../components/imports"' not in source
    assert 'from "../components/projects"' not in source


def test_workbench_reports_route_state_is_split_from_shell() -> None:
    shell_source = (REPO_ROOT / "frontend/src/workbench/WorkbenchShell.tsx").read_text(
        encoding="utf-8"
    )
    reports_state_source = (REPO_ROOT / "frontend/src/workbench/useReportsRouteState.ts").read_text(
        encoding="utf-8"
    )

    assert 'import { useReportsRouteState } from "./useReportsRouteState"' in shell_source
    assert "ReportsService" not in shell_source
    assert "function reportDownloadUrl" not in shell_source
    assert "function downloadReportArtifact" not in shell_source
    assert "useReportsRouteState({" in shell_source
    assert "ReportsService" in reports_state_source
    assert "function reportDownloadUrl" in reports_state_source
    assert "function downloadReportArtifact" in reports_state_source


def test_findings_queue_uses_vpw_product_surfaces() -> None:
    source = (REPO_ROOT / "frontend/src/components/findings/RemediationQueue.tsx").read_text(
        encoding="utf-8"
    )

    assert "@/components/vpw" in source
    assert "VpwMetricCard" in source
    assert "VpwEmptyState" in source
    assert "VpwStatusBanner" in source
    assert "@/components/ui/card" not in source
    assert "@/components/ui/badge" not in source
    assert "bg-gradient-to-br" not in source
    assert "rounded-2xl" not in source


def test_dashboard_and_finding_detail_use_vpw_surfaces() -> None:
    dashboard_paths = [
        REPO_ROOT / "frontend/src/components/dashboard/RiskOperationsDashboard.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/TopRemediationQueue.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/ProviderFreshnessPanel.tsx",
        REPO_ROOT / "frontend/src/components/risk/MetricCard.tsx",
    ]
    finding_detail_paths = [
        REPO_ROOT / "frontend/src/components/finding-detail/FindingDetailRoute.tsx",
        REPO_ROOT / "frontend/src/components/finding-detail/FindingDetailHero.tsx",
        REPO_ROOT / "frontend/src/components/finding-detail/WhyPriorityPanel.tsx",
        REPO_ROOT / "frontend/src/components/finding-detail/FindingEvidenceTab.tsx",
        REPO_ROOT / "frontend/src/components/finding-detail/FindingTtpContextTab.tsx",
        REPO_ROOT / "frontend/src/components/finding-detail/FindingHistoryTab.tsx",
    ]

    for path in dashboard_paths + finding_detail_paths:
        source = path.read_text(encoding="utf-8")

        assert "components/ui/card" not in source, path

    assert "VpwSurface" in dashboard_paths[0].read_text(encoding="utf-8")
    assert "VpwPanel" in dashboard_paths[1].read_text(encoding="utf-8")
    assert "VpwPanel" in dashboard_paths[2].read_text(encoding="utf-8")
    assert "VpwSurface" in dashboard_paths[3].read_text(encoding="utf-8")
    assert "VpwStatusBanner" in finding_detail_paths[0].read_text(encoding="utf-8")
    assert "VpwSurface" in finding_detail_paths[1].read_text(encoding="utf-8")
    assert "VpwKeyValueList" in finding_detail_paths[2].read_text(encoding="utf-8")
    assert "VpwDataTable" in finding_detail_paths[3].read_text(encoding="utf-8")
    assert "VpwDataTable" in finding_detail_paths[4].read_text(encoding="utf-8")
    assert "VpwTimeline" in finding_detail_paths[5].read_text(encoding="utf-8")
    dashboard_source = dashboard_paths[0].read_text(encoding="utf-8")
    assert "rounded-2xl" not in dashboard_source
    assert "bg-gradient-to-br" not in dashboard_source
    assert "bg-linear-to-br" not in dashboard_source
    assert "bg-slate-900" not in dashboard_source


def test_frontend_css_drops_unused_pre_vpw_shell_classes() -> None:
    source = (REPO_ROOT / "frontend/src/index.css").read_text(encoding="utf-8")

    removed_selectors = {
        ".app-shell",
        ".dashboard-empty",
        ".dashboard-hero",
        ".dashboard-provider-badge",
        ".data-services-summary",
        ".metric-grid",
        ".nav-item",
        ".nav-list",
        ".project-context",
        ".sidebar-footer",
        ".status-strip",
    }

    assert {selector for selector in removed_selectors if selector in source} == set()


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


def test_reporter_facade_reexports_private_reporting_renderers() -> None:
    imports = _imported_modules("src/vuln_prioritizer/reporter.py")

    assert "vuln_prioritizer.reporting_html" in imports
    assert "vuln_prioritizer.reporting_markdown" in imports
    assert "vuln_prioritizer.reporting_snapshot" in imports
    assert "vuln_prioritizer.reporting_state" in imports


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

    assert {"mkdocs", "pytest-cov"}.issubset(package_names)
    assert "playwright" not in package_names


def test_sdist_manifest_excludes_partial_test_tree() -> None:
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")

    assert "prune tests" in manifest
