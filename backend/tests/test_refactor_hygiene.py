from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent
SRC_ROOT = ROOT / "src" / "vuln_prioritizer"


def _assert_metric_strip_adapter(source: str, label: str) -> None:
    assert "MetricStrip" in source, label
    assert "VpwMetricStrip" not in source, label
    assert "VpwCompactMetric" not in source, label


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
        "load_analysis_context_profile",
        "load_analysis_provider_snapshot",
        "load_analysis_waiver_rules",
        "load_asset_records",
        "load_vex_statements",
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
        "vuln_prioritizer.services.analysis_explain",
        "vuln_prioritizer.services.analysis_findings",
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


def test_analysis_pipeline_delegates_quality_and_explain_helpers() -> None:
    pipeline_source = (ROOT / "src/vuln_prioritizer/services/analysis_pipeline.py").read_text(
        encoding="utf-8"
    )
    findings_source = (ROOT / "src/vuln_prioritizer/services/analysis_findings.py").read_text(
        encoding="utf-8"
    )
    quality_source = (ROOT / "src/vuln_prioritizer/services/analysis_quality.py").read_text(
        encoding="utf-8"
    )
    explain_source = (ROOT / "src/vuln_prioritizer/services/analysis_explain.py").read_text(
        encoding="utf-8"
    )

    assert "vuln_prioritizer.services.analysis_findings" in pipeline_source
    assert "vuln_prioritizer.services.analysis_quality" in findings_source
    assert "def build_findings" not in pipeline_source
    assert "def build_findings" in findings_source
    assert "def attach_provider_data_quality_flags" not in pipeline_source
    assert "def _finding_data_quality_confidence" not in pipeline_source
    assert "def attach_provider_data_quality_flags" in quality_source
    assert "def _finding_data_quality_confidence" in quality_source
    assert "vuln_prioritizer.services.analysis_explain" in pipeline_source
    assert "Compatibility wrapper for the focused explain module." in pipeline_source
    assert "Compatibility wrapper for saved-analysis explain results." in pipeline_source
    assert "build_inline_input" not in pipeline_source
    assert "def prepare_explain" in explain_source
    assert "def prepare_saved_explain" in explain_source


def test_enrichment_service_delegates_snapshot_quality_and_result_helpers() -> None:
    source = (ROOT / "src/vuln_prioritizer/services/enrichment.py").read_text(encoding="utf-8")
    snapshot_source = (ROOT / "src/vuln_prioritizer/services/enrichment_snapshot.py").read_text(
        encoding="utf-8"
    )
    quality_source = (ROOT / "src/vuln_prioritizer/services/enrichment_quality.py").read_text(
        encoding="utf-8"
    )
    results_source = (ROOT / "src/vuln_prioritizer/services/enrichment_results.py").read_text(
        encoding="utf-8"
    )

    assert "vuln_prioritizer.services.enrichment_snapshot" in source
    assert "vuln_prioritizer.services.enrichment_quality" in source
    assert "vuln_prioritizer.services.enrichment_results" in source
    assert "class EnrichmentService" in source
    assert "def _provider_data_quality_flags" not in source
    assert "def _append_provider_error_flag" not in source
    assert "def _snapshot_defensive_contexts" not in source
    assert "def _merge_provider_results" not in source
    assert "def provider_enrichment_quality_flags" in quality_source
    assert "def snapshot_defensive_contexts" in snapshot_source
    assert "def merge_provider_results" in results_source
    assert "def build_fallback_diagnostics" in results_source
    assert len(source.splitlines()) <= 430
    assert len(snapshot_source.splitlines()) <= 80
    assert len(quality_source.splitlines()) <= 220
    assert len(results_source.splitlines()) <= 120


def test_prioritization_service_delegates_sorting_ranking_and_attack_helpers() -> None:
    source = (ROOT / "src/vuln_prioritizer/services/prioritization.py").read_text(encoding="utf-8")
    sorting_source = (ROOT / "src/vuln_prioritizer/services/prioritization_sorting.py").read_text(
        encoding="utf-8"
    )
    ranking_source = (ROOT / "src/vuln_prioritizer/services/prioritization_ranking.py").read_text(
        encoding="utf-8"
    )
    attack_source = (ROOT / "src/vuln_prioritizer/services/prioritization_attack.py").read_text(
        encoding="utf-8"
    )

    assert "vuln_prioritizer.services.prioritization_sorting" in source
    assert "vuln_prioritizer.services.prioritization_ranking" in source
    assert "vuln_prioritizer.services.prioritization_attack" in source
    assert "class PrioritizationService" in source
    assert "def _finding_sort_key" not in source
    assert "def _comparison_sort_key" not in source
    assert "def _operational_sort_key" not in source
    assert "def _context_rank_reasons" not in source
    assert "def _attack_context_summary" not in source
    assert "def sort_prioritized_findings" in sorting_source
    assert "def sort_comparison_findings" in sorting_source
    assert "def assign_operational_ranks" in ranking_source
    assert "def _context_rank_reasons" in ranking_source
    assert "def build_attack_context_summary" in attack_source
    assert len(source.splitlines()) <= 300
    assert len(sorting_source.splitlines()) <= 130
    assert len(ranking_source.splitlines()) <= 240
    assert len(attack_source.splitlines()) <= 70


def test_service_modules_do_not_import_cli_adapter_modules() -> None:
    for path in _python_module_paths("services"):
        imports = _imported_modules(str(path.relative_to(ROOT)))

        assert not {
            module for module in imports if module.startswith("vuln_prioritizer.cli_support")
        }, path


def test_app_service_modules_do_not_import_through_service_facade() -> None:
    service_root = ROOT / "app" / "services"
    violations: dict[str, list[int]] = {}
    for path in sorted(service_root.rglob("*.py")):
        if path.name == "__init__.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        line_numbers = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "app.services"
        ]
        if line_numbers:
            violations[str(path.relative_to(ROOT))] = sorted(line_numbers)

    assert violations == {}


def test_workbench_app_imports_domain_options_not_cli_options() -> None:
    violations: list[str] = []
    for path in sorted((ROOT / "app").rglob("*.py")):
        imports = _imported_modules(str(path.relative_to(ROOT)))
        if "vuln_prioritizer.cli_options" in imports:
            violations.append(str(path.relative_to(ROOT)))

    assert violations == []


def test_workbench_backend_does_not_import_legacy_layers() -> None:
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


def test_import_upload_route_delegates_to_application_service() -> None:
    route_source = (ROOT / "app/api/routes/imports.py").read_text(encoding="utf-8")
    service_source = (ROOT / "app/services/import_execution.py").read_text(encoding="utf-8")
    parsing_source = (ROOT / "app/services/import_execution_parsing.py").read_text(encoding="utf-8")
    route_imports = _imported_modules("app/api/routes/imports.py")

    assert len(route_source.splitlines()) <= 140
    assert "app.services.import_execution" in route_imports
    assert "AnalysisService" not in route_source
    assert "build_importer_registry" not in route_source
    assert "RunRepository" not in route_source
    assert "def execute_project_import_upload" in service_source
    assert "AnalysisService" in service_source
    assert "app.services.import_execution_parsing" in service_source
    assert "build_importer_registry" in parsing_source


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


def test_workbench_report_contracts_are_split_from_renderer_facade() -> None:
    imports = _imported_modules("app/services/reports.py")
    source = (ROOT / "app/services/reports.py").read_text(encoding="utf-8")
    service_payload_source = (ROOT / "app/services/report_service_payload.py").read_text(
        encoding="utf-8"
    )
    service_attack_source = (ROOT / "app/services/report_service_attack.py").read_text(
        encoding="utf-8"
    )
    service_persistence_source = (ROOT / "app/services/report_service_persistence.py").read_text(
        encoding="utf-8"
    )
    contracts_source = (ROOT / "app/services/report_contracts.py").read_text(encoding="utf-8")
    models_source = (ROOT / "app/services/report_models.py").read_text(encoding="utf-8")
    renderer_common_source = (ROOT / "app/services/report_renderer_common.py").read_text(
        encoding="utf-8"
    )
    formatting_source = (ROOT / "app/services/report_formatting.py").read_text(encoding="utf-8")
    renderers_source = (ROOT / "app/services/report_renderers.py").read_text(encoding="utf-8")
    renderers_imports = _imported_modules("app/services/report_renderers.py")
    markdown_source = (ROOT / "app/services/report_markdown.py").read_text(encoding="utf-8")
    markdown_imports = _imported_modules("app/services/report_markdown.py")
    markdown_sections_source = (ROOT / "app/services/report_markdown_sections.py").read_text(
        encoding="utf-8"
    )
    bundle_source = (ROOT / "app/services/report_bundle.py").read_text(encoding="utf-8")
    bundle_imports = _imported_modules("app/services/report_bundle.py")
    bundle_archive_source = (ROOT / "app/services/report_bundle_archive.py").read_text(
        encoding="utf-8"
    )
    bundle_governance_source = (ROOT / "app/services/report_bundle_governance.py").read_text(
        encoding="utf-8"
    )
    bundle_governance_rows_source = (
        ROOT / "app/services/report_bundle_governance_rows.py"
    ).read_text(encoding="utf-8")
    bundle_verification_source = (ROOT / "app/services/report_bundle_verification.py").read_text(
        encoding="utf-8"
    )
    html_source = (ROOT / "app/services/report_html.py").read_text(encoding="utf-8")
    html_imports = _imported_modules("app/services/report_html.py")
    html_styles_source = (ROOT / "app/services/report_html_styles.py").read_text(encoding="utf-8")
    html_governance_source = (ROOT / "app/services/report_html_governance.py").read_text(
        encoding="utf-8"
    )
    html_findings_source = (ROOT / "app/services/report_html_findings.py").read_text(
        encoding="utf-8"
    )
    html_provider_source = (ROOT / "app/services/report_html_provider.py").read_text(
        encoding="utf-8"
    )
    html_narrative_source = (ROOT / "app/services/report_html_narrative.py").read_text(
        encoding="utf-8"
    )
    html_components_source = (ROOT / "app/services/report_html_components.py").read_text(
        encoding="utf-8"
    )
    html_helpers_source = (ROOT / "app/services/report_html_helpers.py").read_text(encoding="utf-8")
    html_helpers_imports = _imported_modules("app/services/report_html_helpers.py")
    html_campaign_facade_source = (ROOT / "app/services/report_html_campaigns.py").read_text(
        encoding="utf-8"
    )
    html_provider_evidence_source = (
        ROOT / "app/services/report_html_provider_evidence.py"
    ).read_text(encoding="utf-8")
    html_common_source = (ROOT / "app/services/report_html_common.py").read_text(encoding="utf-8")
    html_attack_source = (ROOT / "app/services/report_html_attack_context.py").read_text(
        encoding="utf-8"
    )
    html_campaign_model_source = (ROOT / "app/services/report_html_campaign_model.py").read_text(
        encoding="utf-8"
    )
    html_campaign_rendering_source = (
        ROOT / "app/services/report_html_campaign_rendering.py"
    ).read_text(encoding="utf-8")
    html_provider_freshness_source = (
        ROOT / "app/services/report_html_provider_freshness.py"
    ).read_text(encoding="utf-8")
    html_evidence_package_source = (
        ROOT / "app/services/report_html_evidence_package.py"
    ).read_text(encoding="utf-8")
    html_decision_source = (ROOT / "app/services/report_html_decision.py").read_text(
        encoding="utf-8"
    )
    html_view_model_source = (ROOT / "app/services/report_html_view_model.py").read_text(
        encoding="utf-8"
    )
    service_payload_attack_source = (
        ROOT / "app/services/report_service_payload_attack.py"
    ).read_text(encoding="utf-8")
    html_document_source = (ROOT / "app/services/report_html_document.py").read_text(
        encoding="utf-8"
    )
    sarif_source = (ROOT / "app/services/report_sarif.py").read_text(encoding="utf-8")
    api_reports_test_source = (ROOT / "tests/api/test_workbench_reports_api.py").read_text(
        encoding="utf-8"
    )

    assert "app.services.report_contracts" in imports
    assert "app.services.report_models" in imports
    assert "app.services.report_renderers" in imports
    assert "app.services.report_sarif" in imports
    assert "app.services.report_service_attack" in imports
    assert "app.services.report_service_payload" in imports
    assert "app.services.report_service_persistence" in imports
    assert "app.services.report_formatting" in renderers_imports
    assert "CSV_FINDINGS_COLUMNS = [" not in source
    assert "EXECUTIVE_REPORT_CSS = " not in source
    assert "def render_markdown_report" not in source
    assert "def render_evidence_bundle_zip" not in source
    assert "ReportRepository" not in source
    assert "build_project_governance_rollups_payload" not in source
    assert "build_attack_navigator_layer_payload" not in source
    assert "def _run_findings" not in source
    assert "def run_findings" in service_payload_source
    assert "def build_report_payload" in service_payload_source
    assert "def run_attack_contexts" in service_attack_source
    assert "def attack_navigator_layer" in service_attack_source
    assert "def persist_text_report" in service_persistence_source
    assert "def persist_binary_report" in service_persistence_source
    assert "class MarkdownReportPayload" not in source
    assert len(source.splitlines()) <= 330
    assert len(service_payload_source.splitlines()) <= 130
    assert len(service_attack_source.splitlines()) <= 70
    assert len(service_persistence_source.splitlines()) <= 190
    assert "import vuln_prioritizer.workbench_report_contracts" in contracts_source
    assert "CSV_FINDINGS_COLUMNS = _workbench_report_contracts.CSV_FINDINGS_COLUMNS" in (
        contracts_source
    )
    assert "CSV_FINDINGS_COLUMNS = [" not in api_reports_test_source
    assert (
        "from app.services.report_contracts import CSV_FINDINGS_COLUMNS" in api_reports_test_source
    )
    assert "REPORT_FILENAME_EVIDENCE_BUNDLE" in contracts_source
    assert "from vuln_prioritizer.model_base import StrictModel" in models_source
    assert "class ReportPayload(StrictModel)" in models_source
    assert "class ReportFinding(StrictModel)" in models_source
    assert "class ReportProviderSnapshot(StrictModel)" in models_source
    assert "class RemediationCampaign(StrictModel)" in models_source
    assert "class ExecutiveReportViewModel(StrictModel)" in models_source
    assert "class AnalysisResultV1(StrictModel)" in models_source
    assert "MarkdownReportPayload: TypeAlias = ReportPayload" in models_source
    assert "MarkdownReportFinding: TypeAlias = ReportFinding" in models_source
    assert "MarkdownProviderSnapshot: TypeAlias = ReportProviderSnapshot" in models_source
    campaign_model_block = models_source.split("class RemediationCampaign", maxsplit=1)[1].split(
        "class ReportIdentity", maxsplit=1
    )[0]
    view_model_block = models_source.split("class ExecutiveReportViewModel", maxsplit=1)[1].split(
        "class AnalysisResultV1", maxsplit=1
    )[0]
    assert "dict[str, Any]" not in campaign_model_block
    assert "dict[str, Any]" not in view_model_block
    assert "from dataclasses import replace" not in renderer_common_source
    assert "from dataclasses import replace" not in service_payload_attack_source
    assert "replace(" not in renderer_common_source
    assert "replace(" not in service_payload_attack_source
    assert "def safe_cell" in formatting_source
    assert "def csv_safe_cell" in formatting_source
    assert len(renderers_source.splitlines()) <= 120
    assert "EXECUTIVE_REPORT_CSS = " not in renderers_source
    assert "def render_markdown_report" in markdown_source
    assert "app.services.report_markdown_sections" in markdown_imports
    assert "def _markdown_governance_section" not in markdown_source
    assert "def _markdown_governance_section" in markdown_sections_source
    assert "def _markdown_detection_coverage_section" in markdown_sections_source
    assert len(markdown_source.splitlines()) <= 220
    assert len(markdown_sections_source.splitlines()) <= 260
    assert "EXECUTIVE_REPORT_CSS = " in html_source
    assert "app.services.report_html_styles" in html_imports
    assert "app.services.report_html_governance" in html_imports
    assert "app.services.report_html_findings" in html_imports
    assert "app.services.report_html_provider" in html_imports
    assert "app.services.report_html_narrative" in html_imports
    assert "app.services.report_html_components" in html_imports
    assert "def _html_governance_rollups" not in html_source
    assert "def _html_governance_rollups" in html_governance_source
    assert "def _html_top_risk_row" not in html_source
    assert "def _html_top_risk_row" in html_findings_source
    assert "def _html_provider_snapshot" not in html_source
    assert "def _html_provider_snapshot" in html_provider_source
    assert "def _executive_summary_text" not in html_source
    assert "def _executive_summary_text" in html_narrative_source
    assert "def _html_metric" not in html_source
    assert "def _html_metric" in html_components_source
    assert {
        "app.services.report_html_attack_context",
        "app.services.report_html_campaigns",
        "app.services.report_html_common",
        "app.services.report_html_decision",
        "app.services.report_html_document",
        "app.services.report_html_provider_evidence",
        "app.services.report_html_view_model",
    }.issubset(html_helpers_imports)
    assert "def _get_remediation_campaigns_helper" not in html_helpers_source
    assert "def _html_provider_snapshot_helper" not in html_helpers_source
    assert "def build_executive_report_view_model" not in html_source
    assert "def render_html_executive_report_helper" not in html_source
    assert "def _get_remediation_campaigns_helper" in html_campaign_model_source
    assert "def _html_remediation_campaigns_helper" in html_campaign_rendering_source
    assert "campaign[" not in html_campaign_model_source
    assert "campaign[" not in html_campaign_rendering_source
    assert "campaign[" not in html_decision_source
    assert "campaign[" not in html_view_model_source
    assert "def _html_provider_snapshot_helper" in html_provider_freshness_source
    assert "def _html_evidence_package_table_helper" in html_evidence_package_source
    assert "def _action_plan_rows_helper" in html_decision_source
    assert "def build_executive_report_view_model" in html_view_model_source
    assert "def render_html_executive_report_helper" in html_document_source
    assert "EXECUTIVE_REPORT_CSS = " in html_styles_source
    assert len(html_source.splitlines()) <= 190
    assert len(html_styles_source.splitlines()) <= 240
    assert len(html_governance_source.splitlines()) <= 170
    assert len(html_findings_source.splitlines()) <= 70
    assert len(html_provider_source.splitlines()) <= 70
    assert len(html_narrative_source.splitlines()) <= 80
    assert len(html_components_source.splitlines()) <= 40
    assert len(html_helpers_source.splitlines()) <= 180
    assert len(html_campaign_facade_source.splitlines()) <= 70
    assert len(html_provider_evidence_source.splitlines()) <= 40
    assert len(html_common_source.splitlines()) <= 290
    assert len(html_attack_source.splitlines()) <= 190
    assert len(html_campaign_model_source.splitlines()) <= 510
    assert len(html_campaign_rendering_source.splitlines()) <= 510
    assert len(html_provider_freshness_source.splitlines()) <= 420
    assert len(html_evidence_package_source.splitlines()) <= 180
    assert len(html_decision_source.splitlines()) <= 320
    assert len(html_view_model_source.splitlines()) <= 230
    assert len(html_document_source.splitlines()) <= 290
    assert "def render_evidence_bundle_zip" in bundle_source
    assert "app.services.report_bundle_archive" in bundle_imports
    assert "app.services.report_bundle_governance" in bundle_imports
    assert "app.services.report_bundle_verification" in bundle_imports
    assert "def _bundle_file_entry" not in bundle_source
    assert "def _bundle_file_entry" in bundle_archive_source
    assert "def _governance_bundle_entries" not in bundle_source
    assert "def _governance_bundle_entries" in bundle_governance_source
    assert "def _asset_context_rows" not in bundle_governance_source
    assert "def _asset_context_rows" in bundle_governance_rows_source
    assert "def _evidence_bundle_verification_payload" in bundle_verification_source
    assert len(bundle_source.splitlines()) <= 220
    assert len(bundle_archive_source.splitlines()) <= 90
    assert len(bundle_governance_source.splitlines()) <= 210
    assert len(bundle_governance_rows_source.splitlines()) <= 100
    assert len(bundle_verification_source.splitlines()) <= 40
    assert "def render_sarif_report" not in renderers_source
    assert "def render_sarif_report" in sarif_source


def test_report_artifact_validation_is_split_from_route_facade() -> None:
    route_source = (ROOT / "app/api/routes/reports.py").read_text(encoding="utf-8")
    artifact_source = (ROOT / "app/services/report_artifacts.py").read_text(encoding="utf-8")

    assert "app.services.report_artifacts" in route_source
    assert "hashlib" not in route_source
    assert "redact_public_payload" not in route_source
    assert "def validated_report_path" not in route_source
    assert "def validated_report_path" in artifact_source
    assert "class ReportArtifactChecksumError" in artifact_source


def test_provider_status_projection_is_split_from_route_facade() -> None:
    route_source = (ROOT / "app/api/routes/providers.py").read_text(encoding="utf-8")
    status_source = (ROOT / "app/services/provider_status.py").read_text(encoding="utf-8")

    assert "app.services.provider_status" in route_source
    assert "redact_public_payload" not in route_source
    assert "production_safe_settings" not in route_source
    assert "def _snapshot_status" not in route_source
    assert "def provider_status_payload" in status_source
    assert "def provider_update_job_public" in status_source


def test_provider_update_orchestrator_uses_focused_services() -> None:
    source = (ROOT / "app/services/provider_updates.py").read_text(encoding="utf-8")
    imports = _imported_modules("app/services/provider_updates.py")
    constants_source = (ROOT / "app/services/provider_update_constants.py").read_text(
        encoding="utf-8"
    )
    inputs_source = (ROOT / "app/services/provider_update_inputs.py").read_text(encoding="utf-8")
    locking_source = (ROOT / "app/services/provider_update_locking.py").read_text(encoding="utf-8")
    snapshot_source = (ROOT / "app/services/provider_update_snapshot.py").read_text(
        encoding="utf-8"
    )

    assert {
        "app.services.provider_update_constants",
        "app.services.provider_update_errors",
        "app.services.provider_update_inputs",
        "app.services.provider_update_locking",
        "app.services.provider_update_snapshot",
    }.issubset(imports)
    assert "def _provider_update_lock(" not in source
    assert "def _write_provider_snapshot(" not in source
    assert "class ProviderUpdateConflict" not in source
    assert "KevProvider" not in source
    assert "NvdProvider" not in source
    assert "EpssProvider" not in source
    assert "PROVIDER_UPDATE_INPUT_TYPE" in constants_source
    assert "def _normalize_sources" in inputs_source
    assert "def _provider_update_lock(" in locking_source
    assert "def _write_provider_snapshot(" in snapshot_source
    assert len(source.splitlines()) <= 430
    assert len(constants_source.splitlines()) <= 40
    assert len(inputs_source.splitlines()) <= 140
    assert len(locking_source.splitlines()) <= 110
    assert len(snapshot_source.splitlines()) <= 430


def test_attack_payload_service_delegates_normalization_helpers() -> None:
    source = (ROOT / "app/services/attack.py").read_text(encoding="utf-8")
    navigator_source = (ROOT / "app/services/attack_navigator.py").read_text(encoding="utf-8")
    support_source = (ROOT / "app/services/attack_support.py").read_text(encoding="utf-8")

    assert "app.services.attack_support" in source
    assert "app.services.attack_navigator" in source
    assert "def build_project_attack_summary_payload" in source
    assert "def build_attack_navigator_layer_payload" in navigator_source
    assert "def _navigator_technique_payload" in navigator_source
    assert "class TechniqueCandidate" not in source
    assert "def confidence_label" not in source
    assert "def records" not in source
    assert "class TechniqueCandidate" in support_source
    assert "def confidence_label" in support_source
    assert "def latest_contexts_by_finding" in support_source
    assert "def technique_candidates" in support_source
    assert "def records" in support_source
    assert len(source.splitlines()) <= 240
    assert len(navigator_source.splitlines()) <= 190
    assert len(support_source.splitlines()) <= 260


def test_attack_models_are_split_behind_stable_facade() -> None:
    facade_source = (ROOT / "app/models/attack.py").read_text(encoding="utf-8")
    common_source = (ROOT / "app/models/attack_common.py").read_text(encoding="utf-8")
    catalog_source = (ROOT / "app/models/attack_catalog.py").read_text(encoding="utf-8")
    stix_source = (ROOT / "app/models/attack_stix.py").read_text(encoding="utf-8")
    context_source = (ROOT / "app/models/attack_context.py").read_text(encoding="utf-8")
    summary_source = (ROOT / "app/models/attack_summary.py").read_text(encoding="utf-8")

    assert "app.models.attack_catalog" in facade_source
    assert "app.models.attack_stix" in facade_source
    assert "app.models.attack_context" in facade_source
    assert "app.models.attack_summary" in facade_source
    assert "class AttackTacticBase" not in facade_source
    assert "class AttackStixSnapshotBase" not in facade_source
    assert "class FindingAttackContextBase" not in facade_source
    assert "class ProjectAttackSummaryPublic" not in facade_source
    assert "ATTACK_REVIEW_STATUSES" in common_source
    assert "class AttackTacticBase" in catalog_source
    assert "class CveAttackMappingBase" in catalog_source
    assert "class AttackStixSnapshotBase" in stix_source
    assert "class AttackStixTechniqueMitigation" in stix_source
    assert "class FindingAttackContextBase" in context_source
    assert "class ProjectAttackSummaryPublic" in summary_source
    assert len(facade_source.splitlines()) <= 140
    assert len(common_source.splitlines()) <= 60
    assert len(catalog_source.splitlines()) <= 280
    assert len(stix_source.splitlines()) <= 320
    assert len(context_source.splitlines()) <= 150
    assert len(summary_source.splitlines()) <= 100


def test_workbench_import_validation_and_storage_are_split_from_route_facade() -> None:
    imports = _imported_modules("app/api/routes/imports.py")
    upload_helper_imports = _imported_modules("app/api/routes/import_uploads.py")
    source = (ROOT / "app/api/routes/imports.py").read_text(encoding="utf-8")
    execution_source = (ROOT / "app/services/import_execution.py").read_text(encoding="utf-8")
    parsing_source = (ROOT / "app/services/import_execution_parsing.py").read_text(encoding="utf-8")
    parse_failure_source = (ROOT / "app/services/import_execution_parse_failures.py").read_text(
        encoding="utf-8"
    )
    type_source = (ROOT / "app/services/import_execution_types.py").read_text(encoding="utf-8")
    upload_stage_source = (ROOT / "app/services/import_execution_uploads.py").read_text(
        encoding="utf-8"
    )
    upload_prepare_source = (ROOT / "app/services/import_execution_upload_prepare.py").read_text(
        encoding="utf-8"
    )
    upload_storage_source = (ROOT / "app/services/import_execution_upload_storage.py").read_text(
        encoding="utf-8"
    )
    run_state_source = (ROOT / "app/services/import_execution_run_state.py").read_text(
        encoding="utf-8"
    )
    upload_source = (ROOT / "app/services/import_uploads.py").read_text(encoding="utf-8")
    artifact_source = (ROOT / "app/services/import_artifacts.py").read_text(encoding="utf-8")

    assert "app.services.import_execution" in imports
    assert "app.api.routes.import_uploads" in imports
    assert "app.services.import_uploads" in upload_helper_imports
    assert "app.services.import_artifacts" not in imports
    assert "ALLOWED_UPLOAD_SUFFIXES = " not in source
    assert "def read_bounded_upload" not in source
    assert "def store_upload" not in source
    assert "def resolve_workbench_provider_snapshot_path" not in source
    assert "app.services.import_execution_upload_prepare" in upload_stage_source
    assert "app.services.import_execution_upload_storage" in upload_stage_source
    assert "app.services.import_execution_run_state" in upload_stage_source
    assert "app.services.import_uploads" in upload_prepare_source
    assert "app.services.import_uploads" in upload_storage_source
    assert "app.services.import_artifacts" in upload_prepare_source
    assert "ALLOWED_UPLOAD_SUFFIXES = " in upload_source
    assert "def store_upload" in upload_source
    assert "def resolve_workbench_provider_snapshot_path" in artifact_source
    assert "def validate_attack_import_options" in artifact_source
    assert "app.services.import_execution_types" in execution_source
    assert "app.services.import_execution_types" in upload_prepare_source
    assert "app.services.import_execution_types" in upload_storage_source
    assert "app.services.import_execution_types" in run_state_source
    assert "app.services.import_execution_uploads" in execution_source
    assert "app.services.import_execution_parsing" in execution_source
    assert "app.services.import_execution_parse_failures" in execution_source
    assert "class PreparedImportUpload" in type_source
    assert "class ResolvedImportRun" in type_source
    assert "class StoredImportArtifacts" in type_source
    assert "def prepare_import_upload" in upload_prepare_source
    assert "def resolve_import_run" in run_state_source
    assert "def store_prepared_uploads" in upload_storage_source
    assert "def parse_prepared_upload" in parsing_source
    assert "def raise_parse_failure" in parse_failure_source
    assert "def raise_sidecar_parse_failure" in parse_failure_source


def test_findings_page_uses_internal_query_object() -> None:
    repository_source = (ROOT / "app/repositories/findings.py").read_text(encoding="utf-8")
    query_source = (ROOT / "app/repositories/finding_page_query.py").read_text(encoding="utf-8")
    route_source = (ROOT / "app/api/routes/findings.py").read_text(encoding="utf-8")
    github_issue_source = (ROOT / "app/services/github_issues.py").read_text(encoding="utf-8")

    assert "app.repositories.finding_page_query" in repository_source
    assert "class FindingPageQuery" in query_source
    assert "def finding_page_filters" in query_source
    assert "def finding_page_order_by" in query_source
    assert "def list_project_findings_query" in repository_source
    assert "FindingPageQuery(" in route_source
    assert "list_project_findings_query" in route_source
    assert "FindingPageQuery(" in github_issue_source


def test_findings_repository_delegates_aggregate_query_helpers() -> None:
    repository_source = (ROOT / "app/repositories/findings.py").read_text(encoding="utf-8")
    repository_imports = _imported_modules("app/repositories/findings.py")
    summary_source = (ROOT / "app/repositories/finding_summary_query.py").read_text(
        encoding="utf-8"
    )
    governance_source = (ROOT / "app/repositories/finding_governance_query.py").read_text(
        encoding="utf-8"
    )
    attack_source = (ROOT / "app/repositories/finding_attack_query.py").read_text(encoding="utf-8")

    assert "app.repositories.finding_summary_query" in repository_imports
    assert "app.repositories.finding_governance_query" in repository_imports
    assert "app.repositories.finding_attack_query" in repository_imports
    assert "def project_finding_summary_counts" in repository_source
    assert "def project_governance_rollups" in repository_source
    assert "def list_project_attack_summary_inputs" in repository_source
    assert "func.sum(_case_int" not in repository_source
    assert "def _governance_rollup_from_row" not in repository_source
    assert "def project_dashboard_signal_counts" in summary_source
    assert "def project_waiver_finding_counts" in summary_source
    assert "def _governance_rollup_from_row" in governance_source
    assert "def top_cves_for_governance_label" in governance_source
    assert "def list_project_attack_summary_inputs" in attack_source
    assert len(repository_source.splitlines()) <= 430
    assert len(summary_source.splitlines()) <= 180
    assert len(governance_source.splitlines()) <= 220
    assert len(attack_source.splitlines()) <= 110


def test_findings_route_delegates_public_projection() -> None:
    route_source = (ROOT / "app/api/routes/findings.py").read_text(encoding="utf-8")
    route_imports = _imported_modules("app/api/routes/findings.py")
    projection_source = (ROOT / "app/services/finding_projection.py").read_text(encoding="utf-8")

    assert "app.services.finding_projection" in route_imports
    assert "def _finding_public" not in route_source
    assert "FindingOccurrencePublic(" not in route_source
    assert "FindingAttackContextDetailPublic(" not in route_source
    assert "redact_value" not in route_source
    assert "select(" not in route_source
    assert "def _finding_public" in projection_source
    assert "FindingOccurrencePublic(" in projection_source
    assert "FindingAttackContextDetailPublic(" in projection_source
    assert "redact_value" in projection_source
    assert len(route_source.splitlines()) <= 140
    assert len(projection_source.splitlines()) <= 480


def test_asset_repository_delegates_projection_and_rescore_rules() -> None:
    repository_source = (ROOT / "app/repositories/assets.py").read_text(encoding="utf-8")
    repository_imports = _imported_modules("app/repositories/assets.py")
    projection_source = (ROOT / "app/domain/asset_context_projection.py").read_text(
        encoding="utf-8"
    )
    rescore_source = (ROOT / "app/domain/asset_rescore.py").read_text(encoding="utf-8")

    assert "app.domain.asset_context_projection" in repository_imports
    assert "app.domain.asset_rescore" in repository_imports
    assert "vuln_prioritizer.scoring" not in repository_imports
    assert "vuln_prioritizer.models" not in repository_imports
    assert "PriorityPolicy" not in repository_source
    assert "build_operational_score" not in repository_source
    assert "def _with_rescore_flag" in projection_source
    assert "def mark_finding_rescore_needed" in rescore_source
    assert "def recalculate_asset_finding" in rescore_source
    assert "build_operational_score" in rescore_source
    assert len(repository_source.splitlines()) <= 280
    assert len(projection_source.splitlines()) <= 400
    assert len(rescore_source.splitlines()) <= 140


def test_legacy_cli_adapter_modules_are_removed() -> None:
    assert not (ROOT / "src/vuln_prioritizer/cli.py").exists()
    assert not (ROOT / "src/vuln_prioritizer/cli_options.py").exists()
    assert not (ROOT / "src/vuln_prioritizer/cli_support").exists()
    assert not (ROOT / "src/vuln_prioritizer/commands").exists()


def test_scoring_operational_rules_are_split_from_priority_facade() -> None:
    scoring_source = (ROOT / "src/vuln_prioritizer/scoring.py").read_text(encoding="utf-8")
    operational_source = (ROOT / "src/vuln_prioritizer/scoring_operational.py").read_text(
        encoding="utf-8"
    )
    rationale_source = (ROOT / "src/vuln_prioritizer/scoring_rationale.py").read_text(
        encoding="utf-8"
    )

    assert "vuln_prioritizer.scoring_operational" in scoring_source
    assert "vuln_prioritizer.scoring_rationale" in scoring_source
    assert "def determine_priority(" in scoring_source
    assert "def build_rationale(" not in scoring_source
    assert "def build_comparison_reason(" not in scoring_source
    assert "def build_operational_score(" not in scoring_source
    assert "def determine_priority_state(" not in scoring_source
    assert "def build_operational_score(" in operational_source
    assert "def determine_priority_state(" in operational_source
    assert "def clamp_operational_score(" in operational_source
    assert "def build_rationale(" in rationale_source
    assert "def build_comparison_reason(" in rationale_source
    assert "def recommended_action(" in rationale_source
    assert len(scoring_source.splitlines()) <= 160
    assert len(operational_source.splitlines()) <= 320
    assert len(rationale_source.splitlines()) <= 220


def test_frontend_routes_use_workbench_route_containers_instead_of_app_facade() -> None:
    app_facade = REPO_ROOT / "frontend/src/App.tsx"
    generated_route_tree = REPO_ROOT / "frontend/src/routeTree.gen.ts"
    old_routes_dir = REPO_ROOT / "frontend/src/routes"
    app_router_source = (REPO_ROOT / "frontend/src/AppRouter.tsx").read_text(encoding="utf-8")
    expected_route_modules = (
        "AssetsRoute",
        "DashboardRoute",
        "FindingDetailRoute",
        "FindingsRoute",
        "ImportsRoute",
        "ProjectsRoute",
        "ProvidersRoute",
        "ReportsRoute",
        "SettingsRoute",
        "WaiversRoute",
    )

    assert not app_facade.exists()
    assert not generated_route_tree.exists()
    assert not old_routes_dir.exists()
    assert "components/app/AppShell" not in app_router_source
    for module_name in expected_route_modules:
        assert f"./workbench/routes/{module_name}" in app_router_source


def test_workbench_shell_mounts_once_in_app_router() -> None:
    app_router_source = (REPO_ROOT / "frontend/src/AppRouter.tsx").read_text(encoding="utf-8")
    route_files = sorted((REPO_ROOT / "frontend/src/workbench/routes").glob("*Route.tsx"))

    assert "<WorkbenchShell routePath={match.routePath}>" in app_router_source
    assert "<RouteParamsProvider params={match.params}>" in app_router_source
    assert route_files
    for path in route_files:
        source = path.read_text(encoding="utf-8")

        assert "WorkbenchRouteApp" not in source, path
        assert "WorkbenchShell" not in source, path
        assert "routePath=" not in source, path

    findings_route = (REPO_ROOT / "frontend/src/workbench/routes/FindingsRoute.tsx").read_text(
        encoding="utf-8"
    )
    finding_detail_route = (
        REPO_ROOT / "frontend/src/workbench/routes/FindingDetailRoute.tsx"
    ).read_text(encoding="utf-8")
    assert "Outlet" not in findings_route
    assert 'routePath: "/findings"' in app_router_source
    assert "findingDetailId=" not in findings_route
    assert "useParams" in finding_detail_route
    assert "findingId=" in finding_detail_route


def test_workbench_shell_is_frame_only_and_routes_own_product_surfaces() -> None:
    source = (REPO_ROOT / "frontend/src/workbench/WorkbenchShell.tsx").read_text(encoding="utf-8")
    route_sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (REPO_ROOT / "frontend/src/workbench/routes").glob("*Route.tsx")
    )

    assert "lazy(() =>" not in source
    assert "ProductAppShell" in source
    assert "WorkbenchProvider" in source
    assert "ProjectsService" not in source
    assert "ImportsService" not in source
    assert "ReportsService" not in source
    assert "WaiversService" not in source
    assert "ApiTokensService" not in source
    assert 'from "../../components/findings/RemediationQueue"' in route_sources
    assert 'from "../../components/dashboard/RiskOperationsDashboard"' in route_sources
    assert 'from "../../components/reports/EvidenceCenter"' in route_sources
    assert 'from "../components/findings"' not in source
    assert 'from "../components/imports"' not in source
    assert 'from "../components/projects"' not in source


def test_app_shell_is_split_into_navigation_and_status_slices() -> None:
    app_root = REPO_ROOT / "frontend/src/components/app"
    shell_source = (app_root / "AppShell.tsx").read_text(encoding="utf-8")
    expected_slices = {
        "AppShellMobileNav.tsx": "export function AppShellMobileNav",
        "AppShellSidebar.tsx": "export function AppShellSidebar",
        "AppShellStatusStrip.tsx": "export function AppShellStatusStrip",
    }

    assert len(shell_source.splitlines()) <= 220
    assert "function readSidebarCollapsed" in shell_source
    assert "function writeSidebarCollapsed" in shell_source
    assert "content.focus({ preventScroll: true })" in shell_source
    assert 'aria-label="Workbench sidebar"' not in shell_source
    assert 'aria-label="Workbench mobile navigation"' not in shell_source
    assert 'aria-label="Workbench status summary"' not in shell_source
    for filename, symbol in expected_slices.items():
        source = (app_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".tsx") in shell_source
        assert len(source.splitlines()) <= 260


def test_design_system_showcase_is_split_and_kept_private() -> None:
    vpw_root = REPO_ROOT / "frontend/src/components/vpw"
    showcase_source = (vpw_root / "VpwDesignSystemShowcase.tsx").read_text(encoding="utf-8")
    index_source = (vpw_root / "index.ts").read_text(encoding="utf-8")
    expected_slices = {
        "VpwDesignSystemShowcaseControls.tsx": "export function VpwDesignSystemShowcaseControls",
        "VpwDesignSystemShowcaseData.tsx": "export const findingRows",
        "VpwDesignSystemShowcaseEvidence.tsx": "export function VpwDesignSystemShowcaseEvidence",
        "VpwDesignSystemShowcaseFrame.tsx": "export function VpwDesignSystemShowcaseFrame",
        "VpwDesignSystemShowcaseFoundations.tsx": (
            "export function VpwDesignSystemShowcaseFoundations"
        ),
        "VpwDesignSystemShowcaseStates.tsx": "export function VpwDesignSystemShowcaseStates",
    }

    assert len(showcase_source.splitlines()) <= 80
    assert "VpwDesignSystemShowcase" not in index_source
    assert "VpwDesignSystemShowcaseEvidence" in showcase_source
    assert "VpwDesignSystemShowcaseFoundations" in showcase_source
    assert "findingRows" not in showcase_source
    foundations_source = (vpw_root / "VpwDesignSystemShowcaseFoundations.tsx").read_text(
        encoding="utf-8"
    )
    assert "VpwDesignSystemShowcaseControls" in foundations_source
    assert "VpwDesignSystemShowcaseFrame" in foundations_source
    assert "VpwDesignSystemShowcaseStates" in foundations_source
    assert len(foundations_source.splitlines()) <= 40
    for filename, symbol in expected_slices.items():
        source = (vpw_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert len(source.splitlines()) <= 200


def test_semantic_badge_model_is_split_behind_facade() -> None:
    vpw_root = REPO_ROOT / "frontend/src/components/vpw"
    facade_source = (vpw_root / "semantic-badge-model.ts").read_text(encoding="utf-8")
    expected_slices = {
        "semantic-badge-types.ts": "export function normalizeSemanticToken",
        "semantic-risk-model.ts": "export function normalizeRiskLevel",
        "semantic-signal-model.ts": "export function normalizeSignalKind",
        "semantic-status-model.ts": "export function normalizeStatus",
    }

    assert len(facade_source.splitlines()) <= 30
    assert "normalizeSemanticToken" not in facade_source
    assert "function normalizeRiskLevel" not in facade_source
    for filename, symbol in expected_slices.items():
        source = (vpw_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".ts") in facade_source
        assert len(source.splitlines()) <= 120


def test_workbench_components_are_split_behind_design_system_facade() -> None:
    vpw_root = REPO_ROOT / "frontend/src/components/vpw"
    facade_source = (vpw_root / "WorkbenchComponents.tsx").read_text(encoding="utf-8")
    expected_slices = {
        "WorkbenchBadges.tsx": "export function StatusBadge",
        "WorkbenchDetail.tsx": "export function DetailDrawer",
        "WorkbenchFeedback.tsx": "export function Callout",
        "WorkbenchSurface.tsx": "export function DataTableFrame",
    }

    assert len(facade_source.splitlines()) <= 10
    assert "export function DetailDrawer" not in facade_source
    assert "export function DataTableFrame" not in facade_source
    for filename, symbol in expected_slices.items():
        source = (vpw_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".tsx") in facade_source
        assert len(source.splitlines()) <= 500
    assert "ui/sheet" not in (vpw_root / "WorkbenchSurface.tsx").read_text(encoding="utf-8")
    assert "VpwDataTable" not in (vpw_root / "WorkbenchDetail.tsx").read_text(encoding="utf-8")


def test_vpw_field_keeps_a11y_helper_logic_split_from_primitives() -> None:
    vpw_root = REPO_ROOT / "frontend/src/components/vpw"
    field_source = (vpw_root / "VpwField.tsx").read_text(encoding="utf-8")
    a11y_source = (vpw_root / "VpwFieldA11y.ts").read_text(encoding="utf-8")

    assert "./VpwFieldA11y" in field_source
    assert "export function VpwField" in field_source
    assert "export function withFieldControlA11y" in a11y_source
    assert "export function mergeIdRefs" in a11y_source
    assert 'nextProps["aria-describedby"]' not in field_source
    assert '"aria-describedby": mergeIdRefs' in a11y_source
    assert len(field_source.splitlines()) <= 190
    assert len(a11y_source.splitlines()) <= 130


def test_workbench_route_shells_delegate_interaction_state() -> None:
    assets_route_source = (REPO_ROOT / "frontend/src/workbench/routes/AssetsRoute.tsx").read_text(
        encoding="utf-8"
    )
    assets_state_source = (
        REPO_ROOT / "frontend/src/workbench/routes/useAssetsRouteState.ts"
    ).read_text(encoding="utf-8")
    assets_route_model_source = (
        REPO_ROOT / "frontend/src/workbench/routes/assets-route-model.ts"
    ).read_text(encoding="utf-8")
    assets_filter_state_source = (
        REPO_ROOT / "frontend/src/workbench/routes/assets-route-filter-state.ts"
    ).read_text(encoding="utf-8")
    imports_route_source = (REPO_ROOT / "frontend/src/workbench/routes/ImportsRoute.tsx").read_text(
        encoding="utf-8"
    )
    imports_container_source = (
        REPO_ROOT / "frontend/src/workbench/routes/ImportsRouteContainer.tsx"
    ).read_text(encoding="utf-8")

    assert 'from "./useAssetsRouteState"' in assets_route_source
    assert "AssetsWorkbench" in assets_route_source
    assert "AssetsService" not in assets_route_source
    assert "useMutation" not in assets_route_source
    assert "useWorkbenchContext" not in assets_route_source
    assert "AssetsService" in assets_state_source
    assert "useWorkbenchContext" in assets_state_source
    assert "AssetsWorkbenchProps" in assets_state_source
    assert "./assets-route-model" in assets_state_source
    assert "./assets-route-filter-state" in assets_state_source
    assert "filterAssets" not in assets_state_source
    assert "summarizeAssets" not in assets_state_source
    assert "buildServiceRollups" not in assets_state_source
    assert "filterAssets" in assets_route_model_source
    assert "export function assetInventoryView" in assets_route_model_source
    assert "export function useAssetFilterState" in assets_filter_state_source
    assert len(assets_route_source.splitlines()) <= 20
    assert len(assets_state_source.splitlines()) <= 400
    assert len(assets_route_model_source.splitlines()) <= 130
    assert len(assets_filter_state_source.splitlines()) <= 110
    assert 'from "./ImportsRouteContainer"' in imports_route_source
    assert "ImportsService" not in imports_route_source
    assert "useMutation" not in imports_route_source
    assert "useWorkbenchContext" not in imports_route_source
    assert "ImportsService" in imports_container_source
    assert "useMutation" in imports_container_source
    assert "useWorkbenchContext" in imports_container_source
    assert len(imports_route_source.splitlines()) <= 10
    assert len(imports_container_source.splitlines()) <= 460


def test_workbench_reports_route_state_is_split_from_shell() -> None:
    shell_source = (REPO_ROOT / "frontend/src/workbench/WorkbenchShell.tsx").read_text(
        encoding="utf-8"
    )
    reports_state_source = (REPO_ROOT / "frontend/src/workbench/useReportsRouteState.ts").read_text(
        encoding="utf-8"
    )
    report_download_source = (REPO_ROOT / "frontend/src/workbench/report-download.ts").read_text(
        encoding="utf-8"
    )

    reports_route_source = (REPO_ROOT / "frontend/src/workbench/routes/ReportsRoute.tsx").read_text(
        encoding="utf-8"
    )

    assert 'import { useReportsRouteState } from "../useReportsRouteState"' in reports_route_source
    assert "ReportsService" not in shell_source
    assert "function reportDownloadUrl" not in shell_source
    assert "download_url" not in shell_source
    assert "function downloadReportArtifact" not in shell_source
    assert "useReportsRouteState({" in reports_route_source
    assert "ReportsService" in reports_state_source
    assert "fetchReportDownload" in reports_state_source
    assert "function downloadReportArtifact" in reports_state_source
    assert "ReportsService.downloadReport" in report_download_source
    assert 'parseAs: "blob"' in report_download_source
    assert "download_url" not in report_download_source


def test_imports_workbench_model_helpers_are_split_from_component() -> None:
    component_source = (
        REPO_ROOT / "frontend/src/components/imports/ImportsWorkbench.tsx"
    ).read_text(encoding="utf-8")
    model_source = (
        REPO_ROOT / "frontend/src/components/imports/imports-workbench-model.ts"
    ).read_text(encoding="utf-8")
    timeline_source = (
        REPO_ROOT / "frontend/src/components/imports/import-run-timeline-model.ts"
    ).read_text(encoding="utf-8")
    records_source = (
        REPO_ROOT / "frontend/src/components/imports/imports-workbench-records.ts"
    ).read_text(encoding="utf-8")

    assert "./imports-workbench-model" in component_source
    assert "export type ImportsWorkbenchProps" not in component_source
    assert "function failedRunCause" not in component_source
    assert "function uploadProgress" not in component_source
    assert "export type ImportsWorkbenchProps" in model_source
    assert "export function failedRunCause" in model_source
    assert "export function uploadProgress" in model_source
    assert "import-run-timeline-model" in model_source
    assert "imports-workbench-records" in model_source
    assert "imports-workbench-records" in timeline_source
    assert "export function importRunTimelineItems" in timeline_source
    assert "export function objectRecord" in records_source
    assert "export function stringValue" in records_source
    assert "function hasProviderEvidence" in timeline_source
    assert "function hasProviderEvidence" not in model_source
    assert len(model_source.splitlines()) <= 260
    assert len(timeline_source.splitlines()) <= 180
    assert len(records_source.splitlines()) <= 20


def test_import_format_metadata_is_split_by_contract_surface() -> None:
    lib_root = REPO_ROOT / "frontend/src/lib"
    facade_source = (lib_root / "import-format-metadata.ts").read_text(encoding="utf-8")
    expected_slices = {
        "import-format-catalog.ts": "export const SUPPORTED_IMPORT_FORMATS",
        "import-format-types.ts": "export type ImportInputType",
        "import-parser-preview.ts": "export async function buildParserPreview",
        "import-readiness.ts": "export function buildImportReadinessChecks",
    }

    assert len(facade_source.splitlines()) <= 40
    assert "SUPPORTED_IMPORT_FORMATS: readonly SupportedFormat[]" not in facade_source
    assert "export async function buildParserPreview" not in facade_source
    assert "export function buildImportReadinessChecks" not in facade_source
    for filename, symbol in expected_slices.items():
        source = (lib_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".ts") in facade_source
        assert len(source.splitlines()) <= 300


def test_frontend_static_demo_data_layer_is_removed() -> None:
    lib_root = REPO_ROOT / "frontend/src/lib"
    demo_data_files = sorted(path.name for path in lib_root.glob("demo-data*.ts"))
    frontend_files = [
        path
        for path in (REPO_ROOT / "frontend/src").rglob("*")
        if path.suffix in {".ts", ".tsx"}
        and "frontend/src/client" not in path.as_posix()
        and not path.name.endswith(".gen.ts")
    ]
    frontend_files.append(REPO_ROOT / "frontend/vite.config.ts")
    forbidden_tokens = {
        "DEMO_MODE_ENABLED",
        "VITE_DEMO_MODE",
        "__VPW_DEMO_MODE__",
        "demo-data",
    }
    offenders = []

    for path in frontend_files:
        source = path.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            if token in source:
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {token}")

    assert demo_data_files == []
    assert offenders == []


def test_import_step_and_run_detail_tabs_are_split_by_surface() -> None:
    imports_root = REPO_ROOT / "frontend/src/components/imports"
    wizard_facade = (imports_root / "NewImportWizardSections.tsx").read_text(encoding="utf-8")
    run_detail_facade = (imports_root / "ImportRunDetailTabs.tsx").read_text(encoding="utf-8")
    expected_wizard_slices = {
        "NewImportChooseSourceStep.tsx": "export function ChooseSourceStep",
        "NewImportContextStep.tsx": "export function AddContextStep",
        "NewImportReviewStep.tsx": "export function ReviewImportStep",
        "NewImportStepNav.tsx": "export function StepNav",
        "NewImportSummaryRail.tsx": "export function SummaryRail",
        "NewImportUploadStep.tsx": "export function UploadFileStep",
    }
    expected_wizard_support_slices = {
        "NewImportReviewPreview.tsx": "export function PreviewSummary",
        "NewImportReviewReadiness.tsx": "export function ReadinessOverview",
        "NewImportReviewShared.tsx": "export function ReviewSectionHeading",
        "NewImportReviewSummary.tsx": "export function ReviewPreflightSummary",
        "NewImportSourceGlyph.tsx": "export function ImportSourceMark",
        "NewImportSourceGlyphIcons.tsx": "export function CveListGlyph",
        "NewImportSourceOption.tsx": "export function FormatOptionCard",
        "NewImportUploadPreview.tsx": "export function ParserPreviewPanel",
    }
    expected_run_detail_slices = {
        "ImportRunDiagnosticsTab.tsx": "export function DiagnosticsTab",
        "ImportRunEvidenceColumns.tsx": "export function buildImportRunEvidenceColumns",
        "ImportRunEvidenceTab.tsx": "export function EvidenceTab",
        "ImportRunFindingsTab.tsx": "export function FindingsTab",
        "ImportRunMetadataTab.tsx": "export function MetadataTab",
        "ImportRunOverviewTab.tsx": "export function OverviewTab",
    }

    assert len(wizard_facade.splitlines()) <= 10
    assert len(run_detail_facade.splitlines()) <= 10
    for filename, symbol in expected_wizard_slices.items():
        source = (imports_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".tsx") in wizard_facade
        assert len(source.splitlines()) <= 560

    assert len((imports_root / "NewImportChooseSourceStep.tsx").read_text().splitlines()) <= 180
    assert len((imports_root / "NewImportReviewStep.tsx").read_text().splitlines()) <= 180
    assert len((imports_root / "NewImportRoute.tsx").read_text().splitlines()) <= 320
    assert len((imports_root / "NewImportUploadStep.tsx").read_text().splitlines()) <= 120
    assert len((imports_root / "NewImportWizardFooter.tsx").read_text().splitlines()) <= 180
    assert len((imports_root / "NewImportFailurePanel.tsx").read_text().splitlines()) <= 120
    route_source = (imports_root / "NewImportRoute.tsx").read_text(encoding="utf-8")
    assert "./NewImportWizardFooter" in route_source
    assert "./NewImportFailurePanel" in route_source
    assert "function WizardFooter" not in route_source
    assert "function ImportFailurePanel" not in route_source

    for filename, symbol in expected_wizard_support_slices.items():
        source = (imports_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert len(source.splitlines()) <= 320

    source_option = (imports_root / "NewImportSourceOption.tsx").read_text(encoding="utf-8")
    source_glyph = (imports_root / "NewImportSourceGlyph.tsx").read_text(encoding="utf-8")
    assert "./NewImportSourceGlyph" in source_option
    assert "./NewImportSourceGlyphIcons" in source_glyph
    assert "function ImportSourceGlyph" not in source_option
    assert "function ImportSourceGlyph" in source_glyph
    assert len(source_option.splitlines()) <= 120
    upload_source = (imports_root / "NewImportUploadStep.tsx").read_text(encoding="utf-8")
    assert "./NewImportUploadPreview" in upload_source
    assert "function ParserPreviewPanel" not in upload_source

    for filename, symbol in expected_run_detail_slices.items():
        source = (imports_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert len(source.splitlines()) <= 260

    evidence_source = (imports_root / "ImportRunEvidenceTab.tsx").read_text(encoding="utf-8")
    evidence_columns_source = (imports_root / "ImportRunEvidenceColumns.tsx").read_text(
        encoding="utf-8"
    )
    assert "./ImportRunEvidenceColumns" in evidence_source
    assert "vpw-table-actions" not in evidence_source
    assert "vpw-table-action-button" in evidence_columns_source
    for filename in expected_run_detail_slices:
        if filename == "ImportRunEvidenceColumns.tsx":
            continue
        assert filename.removesuffix(".tsx") in run_detail_facade

    shared_source = (imports_root / "ImportRunDetailTabShared.tsx").read_text(encoding="utf-8")
    assert "export function RunDetailRows" in shared_source
    assert "export type ImportRunSummary" in shared_source
    assert len(shared_source.splitlines()) <= 160


def test_supported_formats_route_is_split_from_detail_and_filter_surfaces() -> None:
    imports_root = REPO_ROOT / "frontend/src/components/imports"
    route_source = (imports_root / "SupportedFormatsRoute.tsx").read_text(encoding="utf-8")
    expected_slices = {
        "SupportedFormatsColumns.tsx": "export function buildSupportedFormatColumns",
        "SupportedFormatDetailPanel.tsx": "export function SupportedFormatDetailPanel",
        "SupportedFormatsFilters.tsx": "export function SupportedFormatsFilters",
        "supported-formats-route-model.ts": "export function filterSupportedFormats",
    }

    assert len(route_source.splitlines()) <= 220
    assert "./SupportedFormatsColumns" in route_source
    assert "./SupportedFormatDetailPanel" in route_source
    assert "./SupportedFormatsFilters" in route_source
    assert "./supported-formats-route-model" in route_source
    assert "VpwDataTableColumn" not in route_source
    assert "function SupportedFormatDetailPanel" not in route_source
    assert "function projectSearchString" not in route_source
    for filename, symbol in expected_slices.items():
        source = (imports_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert len(source.splitlines()) <= 160


def test_findings_queue_uses_vpw_product_surfaces() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            REPO_ROOT / "frontend/src/components/findings/RemediationQueue.tsx",
            REPO_ROOT / "frontend/src/components/findings/RemediationQueueView.tsx",
            REPO_ROOT / "frontend/src/components/findings/RemediationQueueFilters.tsx",
            REPO_ROOT / "frontend/src/components/findings/RemediationQueueFilterControls.tsx",
            REPO_ROOT / "frontend/src/components/findings/RemediationQueueStates.tsx",
            REPO_ROOT / "frontend/src/components/findings/RemediationQueueSummary.tsx",
        )
    )

    assert "@/components/vpw" in source
    _assert_metric_strip_adapter(source, "findings queue metric strip")
    assert "VpwEmptyState" in source
    assert "VpwStatusBanner" in source
    assert "@/components/ui/card" not in source
    assert "@/components/ui/badge" not in source
    assert "bg-gradient-to-br" not in source
    assert "rounded-2xl" not in source


def test_findings_quick_view_sheet_is_split_from_dialog_facade() -> None:
    findings_root = REPO_ROOT / "frontend/src/components/findings"
    dialog_facade = (findings_root / "RemediationQueueDialogs.tsx").read_text(encoding="utf-8")
    quick_view_source = (findings_root / "RemediationQueueQuickViewSheet.tsx").read_text(
        encoding="utf-8"
    )
    quick_view_model_source = (findings_root / "RemediationQueueQuickViewModel.tsx").read_text(
        encoding="utf-8"
    )
    quick_view_sections_source = (
        findings_root / "RemediationQueueQuickViewSections.tsx"
    ).read_text(encoding="utf-8")
    all_findings_sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(findings_root.glob("*.tsx"))
        if path.name != "RemediationQueueQuickViewSheet.tsx"
    )

    assert len(dialog_facade.splitlines()) <= 5
    assert "./RemediationQueueQuickViewSheet" in dialog_facade
    assert "./RemediationQueueQuickViewSections" in quick_view_source
    assert "./RemediationQueueQuickViewModel" in quick_view_sections_source
    assert "export function QuickViewSheet" in quick_view_source
    assert "export function QuickViewDecisionSummary" in quick_view_sections_source
    assert "export function QuickViewEvidenceSnapshot" in quick_view_sections_source
    assert "export function QuickViewGovernanceSection" in quick_view_sections_source
    assert "function governanceCopy" not in quick_view_source
    assert "export function governanceCopy" in quick_view_model_source
    assert "DrawerFact" not in quick_view_source
    assert len(quick_view_source.splitlines()) <= 220
    assert len(quick_view_model_source.splitlines()) <= 120
    assert len(quick_view_sections_source.splitlines()) <= 430
    assert "WhyDialog" not in all_findings_sources


def test_dashboard_and_finding_detail_use_vpw_surfaces() -> None:
    dashboard_paths = [
        REPO_ROOT / "frontend/src/components/dashboard/RiskOperationsDashboard.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardContextBar.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardContextActions.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardContextProjectPicker.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardProviderWarning.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardRemediationSection.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardSignalOverviewFallback.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/dashboard-summary-model.ts",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardMetricStrip.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardDetailRail.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardOperationsStatePanel.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardRecentRunsPanel.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardDataQualityPanel.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardRecommendedActionsPanel.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardSignalOverview.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardSignalTabs.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardKeyTakeaways.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardRemediationColumns.tsx",
    ]
    finding_detail_paths = [
        REPO_ROOT / "frontend/src/components/finding-detail/FindingDetailRoute.tsx",
        REPO_ROOT / "frontend/src/components/finding-detail/FindingDetailContext.tsx",
        REPO_ROOT / "frontend/src/components/finding-detail/WhyPriorityPanel.tsx",
        REPO_ROOT / "frontend/src/components/finding-detail/FindingEvidenceTab.tsx",
        REPO_ROOT / "frontend/src/components/finding-detail/FindingEvidenceSummaryGrid.tsx",
        REPO_ROOT / "frontend/src/components/finding-detail/FindingOccurrencesPanel.tsx",
        REPO_ROOT / "frontend/src/components/finding-detail/FindingDataQualityPanel.tsx",
        REPO_ROOT / "frontend/src/components/finding-detail/FindingTtpContextTab.tsx",
        REPO_ROOT / "frontend/src/components/finding-detail/FindingTtpContextSections.tsx",
        REPO_ROOT / "frontend/src/components/finding-detail/FindingTtpTechnicalEvidence.tsx",
        REPO_ROOT / "frontend/src/components/finding-detail/FindingHistoryTab.tsx",
    ]

    for path in dashboard_paths + finding_detail_paths:
        source = path.read_text(encoding="utf-8")

        assert "components/ui/card" not in source, path

    dashboard_source = dashboard_paths[0].read_text(encoding="utf-8")
    dashboard_context_source = dashboard_paths[1].read_text(encoding="utf-8")
    dashboard_context_actions_source = dashboard_paths[2].read_text(encoding="utf-8")
    dashboard_context_project_picker_source = dashboard_paths[3].read_text(encoding="utf-8")
    dashboard_summary_source = dashboard_paths[7].read_text(encoding="utf-8")
    dashboard_metric_strip_source = dashboard_paths[8].read_text(encoding="utf-8")
    dashboard_detail_rail_source = dashboard_paths[9].read_text(encoding="utf-8")
    dashboard_operations_source = dashboard_paths[10].read_text(encoding="utf-8")
    dashboard_recent_runs_source = dashboard_paths[11].read_text(encoding="utf-8")
    dashboard_data_quality_source = dashboard_paths[12].read_text(encoding="utf-8")
    dashboard_recommended_actions_source = dashboard_paths[13].read_text(encoding="utf-8")
    dashboard_signal_overview_source = dashboard_paths[14].read_text(encoding="utf-8")
    dashboard_signal_tabs_source = dashboard_paths[15].read_text(encoding="utf-8")
    dashboard_key_takeaways_source = dashboard_paths[16].read_text(encoding="utf-8")
    dashboard_remediation_columns_source = dashboard_paths[17].read_text(encoding="utf-8")
    finding_context_source = finding_detail_paths[1].read_text(encoding="utf-8")
    assert "DashboardProviderWarning" in dashboard_source
    assert "DashboardSignalOverviewFallback" in dashboard_source
    assert "DashboardContextBar" in dashboard_source
    assert "DashboardMetricStrip" in dashboard_source
    assert "DashboardDetailRail" in dashboard_source
    assert "dashboard-summary-model" in dashboard_source
    assert "VpwCommandPanel" in dashboard_context_source
    assert "DashboardContextActions" in dashboard_context_source
    assert "DashboardContextProjectPicker" in dashboard_context_source
    assert "ProviderStatusBadge" in dashboard_context_actions_source
    assert "SelectTrigger" in dashboard_context_project_picker_source
    assert "buildDashboardMetricSummaries" in dashboard_summary_source
    assert "rankedDashboardQueueFindings" in dashboard_summary_source
    assert "./DashboardRemediationColumns" in dashboard_paths[5].read_text(encoding="utf-8")
    assert "SheetContent" not in dashboard_paths[5].read_text(encoding="utf-8")
    assert "vpw-table-actions" not in dashboard_paths[5].read_text(encoding="utf-8")
    assert "buildDashboardRemediationColumns" in dashboard_remediation_columns_source
    assert "vpw-table-actions" in dashboard_remediation_columns_source
    assert "vpw-table-action-button" in dashboard_remediation_columns_source
    assert "DetailDrawer" in dashboard_remediation_columns_source
    assert "./DashboardOperationsStatePanel" in dashboard_detail_rail_source
    assert "./DashboardRecentRunsPanel" in dashboard_detail_rail_source
    assert "./DashboardDataQualityPanel" in dashboard_detail_rail_source
    assert "./DashboardRecommendedActionsPanel" in dashboard_detail_rail_source
    assert "DashboardOperationsStatePanel" in dashboard_operations_source
    assert "ProviderStatusBadge" in dashboard_operations_source
    assert "DashboardRecentRunsPanel" in dashboard_recent_runs_source
    assert "runBadgeTone" in dashboard_recent_runs_source
    assert "DashboardDataQualityPanel" in dashboard_data_quality_source
    assert "DashboardRecommendedActionsPanel" in dashboard_recommended_actions_source
    assert "RECOMMENDED_ACTIONS" in dashboard_recommended_actions_source
    assert "./DashboardSignalTabs" in dashboard_signal_overview_source
    assert "./DashboardKeyTakeaways" in dashboard_signal_overview_source
    assert "ChartCard" not in dashboard_signal_overview_source
    assert "TabsContent" not in dashboard_signal_overview_source
    assert "DashboardSignalTabs" in dashboard_signal_tabs_source
    assert "ChartCard" in dashboard_signal_tabs_source
    assert "DashboardPriorityChart" in dashboard_signal_tabs_source
    assert "DashboardKeyTakeaways" in dashboard_key_takeaways_source
    assert "CheckCircle2" in dashboard_key_takeaways_source
    _assert_metric_strip_adapter(
        dashboard_metric_strip_source,
        "dashboard metric strip",
    )
    assert len(dashboard_source.splitlines()) <= 340
    assert len(dashboard_context_source.splitlines()) <= 90
    assert len(dashboard_context_actions_source.splitlines()) <= 130
    assert len(dashboard_context_project_picker_source.splitlines()) <= 80
    assert len(dashboard_summary_source.splitlines()) <= 180
    assert len(dashboard_metric_strip_source.splitlines()) <= 90
    assert len(dashboard_detail_rail_source.splitlines()) <= 80
    assert len(dashboard_operations_source.splitlines()) <= 120
    assert len(dashboard_recent_runs_source.splitlines()) <= 90
    assert len(dashboard_data_quality_source.splitlines()) <= 110
    assert len(dashboard_recommended_actions_source.splitlines()) <= 130
    assert len(dashboard_signal_overview_source.splitlines()) <= 110
    assert len(dashboard_signal_tabs_source.splitlines()) <= 260
    assert len(dashboard_key_takeaways_source.splitlines()) <= 70
    assert len(dashboard_paths[5].read_text(encoding="utf-8").splitlines()) <= 140
    assert len(dashboard_remediation_columns_source.splitlines()) <= 220
    assert "VpwSurface" in dashboard_paths[4].read_text(encoding="utf-8")
    assert "VpwSurface" in dashboard_paths[5].read_text(encoding="utf-8")
    assert "VpwDataTable" in dashboard_paths[5].read_text(encoding="utf-8")
    assert "VpwSurface" in dashboard_paths[6].read_text(encoding="utf-8")
    _assert_metric_strip_adapter(
        dashboard_paths[8].read_text(encoding="utf-8"),
        "dashboard route metric strip",
    )
    assert "VpwSurface" in dashboard_operations_source
    assert "VpwSurface" in dashboard_recent_runs_source
    assert "VpwSurface" in dashboard_data_quality_source
    assert "VpwSurface" in dashboard_recommended_actions_source
    assert "VpwSurface" in dashboard_signal_overview_source
    assert "VpwStatusBanner" in finding_detail_paths[0].read_text(encoding="utf-8")
    assert "VpwCommandPanel" in finding_context_source
    _assert_metric_strip_adapter(finding_context_source, "finding detail metric strip")
    assert "finding-decision-brief__facts" in finding_detail_paths[2].read_text(encoding="utf-8")
    assert "FindingEvidenceSummaryGrid" in finding_detail_paths[3].read_text(encoding="utf-8")
    assert "FindingOccurrencesPanel" in finding_detail_paths[3].read_text(encoding="utf-8")
    assert "FindingDataQualityPanel" in finding_detail_paths[3].read_text(encoding="utf-8")
    assert "VpwDataTable" not in finding_detail_paths[3].read_text(encoding="utf-8")
    finding_occurrences_source = finding_detail_paths[5].read_text(encoding="utf-8")
    finding_occurrences_columns_source = (
        REPO_ROOT / "frontend/src/components/finding-detail/FindingOccurrencesColumns.tsx"
    ).read_text(encoding="utf-8")
    assert "finding-evidence-grid" in finding_detail_paths[4].read_text(encoding="utf-8")
    assert "VpwDataTable" in finding_occurrences_source
    assert "./FindingOccurrencesColumns" in finding_occurrences_source
    assert "VpwDataTableColumn" not in finding_occurrences_source
    assert "buildFindingOccurrenceColumns" in finding_occurrences_columns_source
    assert "Owner" in finding_occurrences_columns_source
    assert "finding-data-quality-list" in finding_detail_paths[6].read_text(encoding="utf-8")
    assert "VpwDataTable" not in finding_detail_paths[7].read_text(encoding="utf-8")
    assert "FindingTtpContextSections" in finding_detail_paths[7].read_text(encoding="utf-8")
    assert "./FindingTtpTechnicalEvidence" in finding_detail_paths[7].read_text(encoding="utf-8")
    assert "VpwCommandPanel" in finding_detail_paths[8].read_text(encoding="utf-8")
    assert "VpwDataTable" in finding_detail_paths[9].read_text(encoding="utf-8")
    assert "techniqueColumns" in finding_detail_paths[9].read_text(encoding="utf-8")
    assert len(finding_detail_paths[3].read_text(encoding="utf-8").splitlines()) <= 60
    assert len(finding_detail_paths[4].read_text(encoding="utf-8").splitlines()) <= 70
    assert len(finding_occurrences_source.splitlines()) <= 160
    assert len(finding_occurrences_columns_source.splitlines()) <= 130
    assert len(finding_detail_paths[6].read_text(encoding="utf-8").splitlines()) <= 80
    assert len(finding_detail_paths[7].read_text(encoding="utf-8").splitlines()) <= 180
    assert len(finding_detail_paths[8].read_text(encoding="utf-8").splitlines()) <= 180
    assert len(finding_detail_paths[9].read_text(encoding="utf-8").splitlines()) <= 130
    assert "VpwTimeline" in finding_detail_paths[10].read_text(encoding="utf-8")
    assert "rounded-2xl" not in dashboard_source
    assert "bg-gradient-to-br" not in dashboard_source
    assert "bg-linear-to-br" not in dashboard_source
    assert "bg-slate-900" not in dashboard_source


def test_finding_detail_model_is_split_by_behavior() -> None:
    model_root = REPO_ROOT / "frontend/src/components/finding-detail"
    facade_source = (model_root / "finding-detail-model.ts").read_text(encoding="utf-8")
    evidence_facade_source = (model_root / "finding-detail-evidence-model.ts").read_text(
        encoding="utf-8"
    )
    expected_top_slices = {
        "finding-detail-attack-model.ts": "export function attackTechniqueRows",
        "finding-detail-evidence-model.ts": "finding-detail-evidence-rows-model",
        "finding-detail-shared.ts": "export function findingHeroSummary",
    }
    expected_evidence_slices = {
        "finding-detail-decision-model.ts": "export function findingDecisionReasonRows",
        "finding-detail-evidence-rows-model.ts": "export function findingEvidenceRows",
        "finding-detail-occurrence-model.ts": "export function findingOccurrenceRows",
    }

    assert len(facade_source.splitlines()) <= 8
    assert len(evidence_facade_source.splitlines()) <= 8
    for filename, symbol in expected_top_slices.items():
        source = (model_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".ts") in facade_source
        assert len(source.splitlines()) <= 380
    for filename, symbol in expected_evidence_slices.items():
        source = (model_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".ts") in evidence_facade_source
        assert len(source.splitlines()) <= 220


def test_findings_search_and_asset_models_are_split_by_behavior() -> None:
    findings_root = REPO_ROOT / "frontend/src/components/findings"
    findings_facade = (findings_root / "findings-search-state.ts").read_text(encoding="utf-8")
    expected_findings_slices = {
        "findings-search-types.ts": "export type FindingsSearchState",
        "findings-search-parser.ts": "export function parseFindingsSearch",
        "findings-search-serialization.ts": "export function findingsSearchToApiParams",
    }
    asset_root = REPO_ROOT / "frontend/src/components/assets"
    asset_facade = (asset_root / "asset-model.ts").read_text(encoding="utf-8")
    expected_asset_slices = {
        "asset-errors.ts": "export function apiErrorMessage",
        "asset-form-model.ts": "export function validateAssetForm",
        "asset-format-model.ts": "export function formatDateTime",
        "asset-filter-model.ts": "export function filterAssets",
        "asset-finding-model.ts": "export function matchesAsset",
        "asset-rollup-model.ts": "export function buildServiceRollups",
        "asset-tone-model.ts": "export function criticalityTone",
    }

    assert len(findings_facade.splitlines()) <= 20
    for filename, symbol in expected_findings_slices.items():
        source = (findings_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".ts") in findings_facade
        assert len(source.splitlines()) <= 220

    assert len(asset_facade.splitlines()) <= 40
    for filename, symbol in expected_asset_slices.items():
        source = (asset_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".ts") in asset_facade
        assert len(source.splitlines()) <= 140


def test_assets_workbench_delegates_drawer_view() -> None:
    asset_root = REPO_ROOT / "frontend/src/components/assets"
    route_source = (asset_root / "AssetsRoute.tsx").read_text(encoding="utf-8")
    drawer_source = (asset_root / "AssetDrawer.tsx").read_text(encoding="utf-8")
    table_source = (asset_root / "AssetTable.tsx").read_text(encoding="utf-8")
    table_columns_source = (asset_root / "AssetTableColumns.tsx").read_text(encoding="utf-8")
    linked_facade_source = (asset_root / "AssetLinkedFindingsPanel.tsx").read_text(encoding="utf-8")
    expected_linked_slices = {
        "AssetDetailContent.tsx": "export function AssetDetailContent",
        "AssetEditContent.tsx": "export function AssetEditContent",
        "AssetLinkedFindingsContent.tsx": "export function AssetLinkedFindingsContent",
    }

    assert "./AssetDrawer" in route_source
    assert "<AssetDrawer state={state}" in route_source
    assert "function AssetDrawerContent" not in route_source
    assert "function assetDrawerTitle" not in route_source
    assert "SheetContent" not in route_source
    assert "export function AssetDrawer" in drawer_source
    assert "function AssetDrawerContent" in drawer_source
    assert "function assetDrawerTitle" in drawer_source
    assert "AssetContextImportForm" in drawer_source
    assert "AssetLinkedFindingsContent" in drawer_source
    assert "./AssetTableColumns" in table_source
    assert "buildAssetColumns" in table_columns_source
    assert "vpw-table-actions" not in table_source
    assert "vpw-table-action-button" in table_columns_source
    assert len(route_source.splitlines()) <= 250
    assert len(drawer_source.splitlines()) <= 180
    assert len(table_source.splitlines()) <= 80
    assert len(table_columns_source.splitlines()) <= 260
    assert len(linked_facade_source.splitlines()) <= 6
    assert "export function AssetLinkedFindingsContent" not in linked_facade_source
    for filename, symbol in expected_linked_slices.items():
        source = (asset_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".tsx") in linked_facade_source
        assert len(source.splitlines()) <= 240


def test_asset_context_forms_are_split_by_view_surface() -> None:
    asset_root = REPO_ROOT / "frontend/src/components/assets"
    facade_source = (asset_root / "AssetContextForm.tsx").read_text(encoding="utf-8")
    expected_slices = {
        "AssetContextForms.tsx": "export function AssetContextForms",
        "AssetContextImportForm.tsx": "export function AssetContextImportForm",
        "AssetForm.tsx": "export function AssetForm",
    }

    assert len(facade_source.splitlines()) <= 6
    assert "export function AssetForm" not in facade_source
    for filename, symbol in expected_slices.items():
        source = (asset_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".tsx") in facade_source
        assert len(source.splitlines()) <= 240


def test_waivers_drawer_delegates_mode_content() -> None:
    waivers_root = REPO_ROOT / "frontend/src/components/waivers"
    drawer_source = (waivers_root / "WaiversWorkbenchDrawer.tsx").read_text(encoding="utf-8")
    content_source = (waivers_root / "WaiversWorkbenchDrawerContent.tsx").read_text(
        encoding="utf-8"
    )
    detail_source = (waivers_root / "WaiversWorkbenchDrawerDetail.tsx").read_text(encoding="utf-8")
    expire_source = (waivers_root / "WaiversWorkbenchDrawerExpire.tsx").read_text(encoding="utf-8")
    form_source = (waivers_root / "WaiversWorkbenchForm.tsx").read_text(encoding="utf-8")

    assert "./WaiversWorkbenchDrawerContent" in drawer_source
    assert "export function WaiverDrawer" in drawer_source
    assert "function WaiverDrawerContent" not in drawer_source
    assert "function WaiverDetailContent" not in drawer_source
    assert "function WaiverExpireContent" not in drawer_source
    assert "DetailDrawer" in drawer_source
    assert "SheetContent" not in drawer_source
    assert "export function WaiverDrawerContent" in content_source
    assert "./WaiversWorkbenchDrawerDetail" in content_source
    assert "./WaiversWorkbenchDrawerExpire" in content_source
    assert "./WaiversWorkbenchForm" in content_source
    assert "export function WaiverDetailContent" in detail_source
    assert "export function WaiverExpireContent" in expire_source
    assert "export function WaiverForm" in form_source
    assert len(drawer_source.splitlines()) <= 60
    assert len(content_source.splitlines()) <= 130
    assert len(detail_source.splitlines()) <= 310
    assert len(expire_source.splitlines()) <= 90
    assert len(form_source.splitlines()) <= 330


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
    registry_imports = _imported_modules("src/vuln_prioritizer/inputs/parser_registry.py")
    asset_context_source = (ROOT / "src/vuln_prioritizer/inputs/asset_context_loader.py").read_text(
        encoding="utf-8"
    )
    vex_source = (ROOT / "src/vuln_prioritizer/inputs/vex_loader.py").read_text(encoding="utf-8")
    format_source = (ROOT / "src/vuln_prioritizer/inputs/format_detection.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse((ROOT / "src/vuln_prioritizer/inputs/loader.py").read_text())
    parse_functions = [
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("parse_")
    ]

    assert {
        "asset_context_loader",
        "format_detection",
        "parser_registry",
        "vex_loader",
    }.issubset(imports)
    assert "parsers" in registry_imports
    assert "def load_asset_context_file" in asset_context_source
    assert "def load_vex_files" in vex_source
    assert "def detect_input_format" in format_source
    assert "def load_asset_context_file" not in (
        ROOT / "src/vuln_prioritizer/inputs/loader.py"
    ).read_text(encoding="utf-8")
    assert "def load_vex_files" not in (ROOT / "src/vuln_prioritizer/inputs/loader.py").read_text(
        encoding="utf-8"
    )
    assert parse_functions == []

    parser_modules = _python_module_paths("inputs/parsers")
    assert parser_modules
    assert len(asset_context_source.splitlines()) <= 380
    assert len(vex_source.splitlines()) <= 140
    assert len(format_source.splitlines()) <= 180
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


def test_legacy_reporter_and_terminal_facades_are_removed() -> None:
    removed_modules = (
        "reporter.py",
        "reporting_state.py",
        "reporting_terminal.py",
        "reporting_terminal_tables.py",
        "reporting_terminal_summary.py",
        "reporting_terminal_explain.py",
        "runtime_config.py",
        "state_store.py",
        "models_state.py",
        "reporting_workbench.py",
        "reporting_io.py",
        "parser.py",
    )

    for module in removed_modules:
        assert not (ROOT / f"src/vuln_prioritizer/{module}").exists()


def test_legacy_cli_evidence_bundle_writer_modules_are_removed() -> None:
    removed_modules = (
        "reporting_evidence.py",
        "reporting_evidence_archive.py",
        "reporting_evidence_attack.py",
        "reporting_evidence_bundle.py",
        "reporting_evidence_governance.py",
        "reporting_evidence_inputs.py",
        "reporting_evidence_provider.py",
        "reporting_evidence_verify.py",
        "sarif_validation.py",
    )

    for module in removed_modules:
        assert not (ROOT / f"src/vuln_prioritizer/{module}").exists()

    imports = _imported_modules("app/services/report_bundle.py")
    assert "app.services.report_bundle_archive_verification" in imports


def test_legacy_domain_reporting_facades_are_removed() -> None:
    removed_modules = (
        "reporting_executive.py",
        "reporting_executive_constants.py",
        "reporting_executive_model.py",
        "reporting_executive_model_artifacts.py",
        "reporting_executive_model_attack.py",
        "reporting_executive_model_builder.py",
        "reporting_executive_model_evidence.py",
        "reporting_executive_model_findings.py",
        "reporting_executive_model_helpers.py",
        "reporting_executive_model_overview.py",
        "reporting_executive_model_provider.py",
        "reporting_executive_model_quality.py",
        "reporting_executive_model_remediation.py",
        "reporting_executive_renderer.py",
        "reporting_executive_sections.py",
        "reporting_executive_sections_attack_charts.py",
        "reporting_executive_sections_charts.py",
        "reporting_executive_sections_chrome.py",
        "reporting_executive_sections_components.py",
        "reporting_executive_sections_evidence.py",
        "reporting_executive_sections_remediation_charts.py",
        "reporting_executive_sections_risk_charts.py",
        "reporting_executive_sections_scatter.py",
        "reporting_executive_sections_summary.py",
        "reporting_executive_sections_top.py",
        "reporting_executive_utils.py",
        "reporting_format.py",
        "reporting_html.py",
        "reporting_markdown.py",
        "reporting_markdown_analysis.py",
        "reporting_payloads.py",
        "reporting_payloads_sarif.py",
        "reporting_payloads_summary.py",
    )

    for module in removed_modules:
        assert not (ROOT / f"src/vuln_prioritizer/{module}").exists()


def test_workbench_frontend_feature_containers_delegate_to_sections() -> None:
    reports_source = (REPO_ROOT / "frontend/src/components/reports/EvidenceCenter.tsx").read_text(
        encoding="utf-8"
    )
    reports_sections_source = (
        REPO_ROOT / "frontend/src/components/reports/EvidenceCenterSections.tsx"
    ).read_text(encoding="utf-8")
    reports_run_context_source = (
        REPO_ROOT / "frontend/src/components/reports/EvidenceCenterRunContext.tsx"
    ).read_text(encoding="utf-8")
    reports_tabs_source = (
        REPO_ROOT / "frontend/src/components/reports/EvidenceCenterTabs.tsx"
    ).read_text(encoding="utf-8")
    reports_lifecycle_source = (
        REPO_ROOT / "frontend/src/components/reports/EvidenceCenterLifecycle.tsx"
    ).read_text(encoding="utf-8")
    reports_artifact_section_source = (
        REPO_ROOT / "frontend/src/components/reports/EvidenceArtifactSection.tsx"
    ).read_text(encoding="utf-8")
    reports_lifecycle_flow_source = (
        REPO_ROOT / "frontend/src/components/reports/EvidenceLifecycleFlow.tsx"
    ).read_text(encoding="utf-8")
    reports_history_source = (
        REPO_ROOT / "frontend/src/components/reports/EvidenceCenterHistory.tsx"
    ).read_text(encoding="utf-8")
    reports_history_columns_source = (
        REPO_ROOT / "frontend/src/components/reports/EvidenceCenterHistoryColumns.tsx"
    ).read_text(encoding="utf-8")
    reports_history_cells_source = (
        REPO_ROOT / "frontend/src/components/reports/EvidenceCenterHistoryCells.tsx"
    ).read_text(encoding="utf-8")
    reports_manifest_source = (
        REPO_ROOT / "frontend/src/components/reports/EvidenceCenterManifest.tsx"
    ).read_text(encoding="utf-8")
    reports_decision_source = (
        REPO_ROOT / "frontend/src/components/reports/EvidenceCenterDecision.tsx"
    ).read_text(encoding="utf-8")
    imports_source = (REPO_ROOT / "frontend/src/components/imports/ImportsWorkbench.tsx").read_text(
        encoding="utf-8"
    )
    imports_sections_source = (
        REPO_ROOT / "frontend/src/components/imports/ImportsWorkbenchSections.tsx"
    ).read_text(encoding="utf-8")
    imports_home_source = (
        REPO_ROOT / "frontend/src/components/imports/ImportsHomeRoute.tsx"
    ).read_text(encoding="utf-8")
    imports_new_source = (
        REPO_ROOT / "frontend/src/components/imports/NewImportRoute.tsx"
    ).read_text(encoding="utf-8")
    imports_run_detail_source = (
        REPO_ROOT / "frontend/src/components/imports/ImportRunDetailRoute.tsx"
    ).read_text(encoding="utf-8")
    imports_diagnostics_source = (
        REPO_ROOT / "frontend/src/components/imports/ImportDiagnosticsDrawer.tsx"
    ).read_text(encoding="utf-8")
    imports_diagnostics_tabs_source = (
        REPO_ROOT / "frontend/src/components/imports/ImportDiagnosticsDrawerTabs.tsx"
    ).read_text(encoding="utf-8")
    imports_formats_source = (
        REPO_ROOT / "frontend/src/components/imports/SupportedFormatsRoute.tsx"
    ).read_text(encoding="utf-8")
    legacy_imports_all_in_one_files = (
        "ImportWizardSteps.tsx",
        "ImportsWorkbenchHero.tsx",
        "ImportsWorkbenchRunDetail.tsx",
        "ImportsWorkbenchSupportedFormats.tsx",
        "ImportsWorkbenchWizard.tsx",
    )
    imports_history_source = (
        REPO_ROOT / "frontend/src/components/imports/ImportsWorkbenchHistory.tsx"
    ).read_text(encoding="utf-8")
    imports_history_columns_source = (
        REPO_ROOT / "frontend/src/components/imports/ImportsWorkbenchHistoryColumns.tsx"
    ).read_text(encoding="utf-8")
    imports_history_actions_source = (
        REPO_ROOT / "frontend/src/components/imports/ImportsWorkbenchHistoryActions.tsx"
    ).read_text(encoding="utf-8")
    findings_source = (
        REPO_ROOT / "frontend/src/components/findings/RemediationQueue.tsx"
    ).read_text(encoding="utf-8")
    findings_table_source = (
        REPO_ROOT / "frontend/src/components/findings/FindingsDataTable.tsx"
    ).read_text(encoding="utf-8")
    findings_table_columns_source = (
        REPO_ROOT / "frontend/src/components/findings/FindingsDataTableColumns.tsx"
    ).read_text(encoding="utf-8")
    vpw_data_table_source = (REPO_ROOT / "frontend/src/components/vpw/VpwDataTable.tsx").read_text(
        encoding="utf-8"
    )
    findings_table_model_source = (
        REPO_ROOT / "frontend/src/components/findings/FindingsDataTableModel.ts"
    ).read_text(encoding="utf-8")
    findings_model_source = (
        REPO_ROOT / "frontend/src/components/findings/remediation-queue-model.ts"
    ).read_text(encoding="utf-8")
    findings_view_source = (
        REPO_ROOT / "frontend/src/components/findings/RemediationQueueView.tsx"
    ).read_text(encoding="utf-8")
    findings_filters_source = (
        REPO_ROOT / "frontend/src/components/findings/RemediationQueueFilters.tsx"
    ).read_text(encoding="utf-8")
    findings_filter_controls_source = (
        REPO_ROOT / "frontend/src/components/findings/RemediationQueueFilterControls.tsx"
    ).read_text(encoding="utf-8")
    projects_source = (
        REPO_ROOT / "frontend/src/components/projects/ProjectsWorkbench.tsx"
    ).read_text(encoding="utf-8")
    projects_sections_source = (
        REPO_ROOT / "frontend/src/components/projects/ProjectsWorkbenchSections.tsx"
    ).read_text(encoding="utf-8")
    projects_overview_source = (
        REPO_ROOT / "frontend/src/components/projects/ProjectsWorkbenchOverview.tsx"
    ).read_text(encoding="utf-8")
    projects_context_source = (
        REPO_ROOT / "frontend/src/components/projects/ProjectContext.tsx"
    ).read_text(encoding="utf-8")
    projects_metrics_source = (
        REPO_ROOT / "frontend/src/components/projects/ProjectMetrics.tsx"
    ).read_text(encoding="utf-8")
    projects_setup_source = (
        REPO_ROOT / "frontend/src/components/projects/ProjectsWorkbenchSetup.tsx"
    ).read_text(encoding="utf-8")
    projects_directory_source = (
        REPO_ROOT / "frontend/src/components/projects/ProjectsWorkbenchDirectory.tsx"
    ).read_text(encoding="utf-8")
    projects_active_source = (
        REPO_ROOT / "frontend/src/components/projects/ProjectsWorkbenchActive.tsx"
    ).read_text(encoding="utf-8")
    projects_active_controls_source = (
        REPO_ROOT / "frontend/src/components/projects/ProjectsWorkbenchActiveControls.tsx"
    ).read_text(encoding="utf-8")
    projects_model_source = (
        REPO_ROOT / "frontend/src/components/projects/projects-workbench-model.ts"
    ).read_text(encoding="utf-8")
    waivers_source = (REPO_ROOT / "frontend/src/components/waivers/WaiversWorkbench.tsx").read_text(
        encoding="utf-8"
    )
    waivers_sections_source = (
        REPO_ROOT / "frontend/src/components/waivers/WaiversWorkbenchSections.tsx"
    ).read_text(encoding="utf-8")
    waivers_context_source = (
        REPO_ROOT / "frontend/src/components/waivers/WaiversWorkbenchContext.tsx"
    ).read_text(encoding="utf-8")
    waivers_create_source = (
        REPO_ROOT / "frontend/src/components/waivers/WaiversWorkbenchCreate.tsx"
    ).read_text(encoding="utf-8")
    waivers_create_guidance_source = (
        REPO_ROOT / "frontend/src/components/waivers/WaiversWorkbenchCreateGuidance.tsx"
    ).read_text(encoding="utf-8")
    waivers_form_source = (
        REPO_ROOT / "frontend/src/components/waivers/WaiversWorkbenchForm.tsx"
    ).read_text(encoding="utf-8")
    waivers_register_source = (
        REPO_ROOT / "frontend/src/components/waivers/WaiversWorkbenchRegister.tsx"
    ).read_text(encoding="utf-8")
    waivers_register_model_source = (
        REPO_ROOT / "frontend/src/components/waivers/waivers-register-model.ts"
    ).read_text(encoding="utf-8")
    waivers_review_source = (
        REPO_ROOT / "frontend/src/components/waivers/WaiversWorkbenchReview.tsx"
    ).read_text(encoding="utf-8")
    waivers_model_source = (
        REPO_ROOT / "frontend/src/components/waivers/waivers-workbench-model.ts"
    ).read_text(encoding="utf-8")
    waiver_form_model_source = (
        REPO_ROOT / "frontend/src/components/waivers/waiver-form-model.ts"
    ).read_text(encoding="utf-8")
    waiver_lifecycle_model_source = (
        REPO_ROOT / "frontend/src/components/waivers/waiver-lifecycle-model.ts"
    ).read_text(encoding="utf-8")
    waiver_scope_model_source = (
        REPO_ROOT / "frontend/src/components/waivers/waiver-scope-model.ts"
    ).read_text(encoding="utf-8")
    waiver_summary_model_source = (
        REPO_ROOT / "frontend/src/components/waivers/waiver-summary-model.ts"
    ).read_text(encoding="utf-8")
    settings_source = (
        REPO_ROOT / "frontend/src/components/settings/SettingsWorkbench.tsx"
    ).read_text(encoding="utf-8")
    settings_sections_source = (
        REPO_ROOT / "frontend/src/components/settings/SettingsWorkbenchSections.tsx"
    ).read_text(encoding="utf-8")
    settings_context_source = (
        REPO_ROOT / "frontend/src/components/settings/SettingsWorkbenchContext.tsx"
    ).read_text(encoding="utf-8")
    settings_overview_source = (
        REPO_ROOT / "frontend/src/components/settings/SettingsWorkbenchOverview.tsx"
    ).read_text(encoding="utf-8")
    settings_tokens_path = (
        REPO_ROOT / "frontend/src/components/settings/SettingsWorkbenchTokens.tsx"
    )
    settings_runtime_source = (
        REPO_ROOT / "frontend/src/components/settings/SettingsWorkbenchRuntime.tsx"
    ).read_text(encoding="utf-8")
    settings_model_source = (
        REPO_ROOT / "frontend/src/components/settings/settings-workbench-model.ts"
    ).read_text(encoding="utf-8")
    providers_source = (
        REPO_ROOT / "frontend/src/components/providers/ProvidersWorkbench.tsx"
    ).read_text(encoding="utf-8")
    providers_sections_source = (
        REPO_ROOT / "frontend/src/components/providers/ProvidersWorkbenchSections.tsx"
    ).read_text(encoding="utf-8")
    providers_diagnostics_source = (
        REPO_ROOT / "frontend/src/components/providers/ProvidersWorkbenchDiagnostics.tsx"
    ).read_text(encoding="utf-8")
    providers_update_job_source = (
        REPO_ROOT / "frontend/src/components/providers/ProviderUpdateJobPanel.tsx"
    ).read_text(encoding="utf-8")
    providers_runtime_facts_source = (
        REPO_ROOT / "frontend/src/components/providers/ProviderRuntimeFactsPanel.tsx"
    ).read_text(encoding="utf-8")
    providers_context_source = (
        REPO_ROOT / "frontend/src/components/providers/ProvidersWorkbenchContext.tsx"
    ).read_text(encoding="utf-8")
    providers_metrics_source = (
        REPO_ROOT / "frontend/src/components/providers/ProvidersWorkbenchMetrics.tsx"
    ).read_text(encoding="utf-8")
    providers_sources_source = (
        REPO_ROOT / "frontend/src/components/providers/ProvidersWorkbenchSources.tsx"
    ).read_text(encoding="utf-8")
    providers_sources_columns_source = (
        REPO_ROOT / "frontend/src/components/providers/ProvidersWorkbenchSourcesColumns.tsx"
    ).read_text(encoding="utf-8")
    providers_snapshot_source = (
        REPO_ROOT / "frontend/src/components/providers/ProvidersWorkbenchSnapshot.tsx"
    ).read_text(encoding="utf-8")
    providers_quality_source = (
        REPO_ROOT / "frontend/src/components/providers/ProvidersWorkbenchQuality.tsx"
    ).read_text(encoding="utf-8")
    providers_model_source = (
        REPO_ROOT / "frontend/src/components/providers/providers-workbench-model.ts"
    ).read_text(encoding="utf-8")
    providers_source_model_source = (
        REPO_ROOT / "frontend/src/components/providers/providers-workbench-source-model.ts"
    ).read_text(encoding="utf-8")
    providers_status_model_source = (
        REPO_ROOT / "frontend/src/components/providers/providers-workbench-status-model.ts"
    ).read_text(encoding="utf-8")
    providers_types_source = (
        REPO_ROOT / "frontend/src/components/providers/providers-workbench-types.ts"
    ).read_text(encoding="utf-8")

    assert "./EvidenceCenterSections" in reports_source
    assert "./ImportsWorkbenchSections" in imports_source
    assert "./RemediationQueueView" in findings_source
    assert "./ProjectsWorkbenchSections" in projects_source
    assert "./projects-workbench-model" in projects_source
    assert "./WaiversWorkbenchSections" in waivers_source
    assert "./waivers-workbench-model" in waivers_source
    assert "./SettingsWorkbenchSections" in settings_source
    assert "./settings-workbench-model" in settings_source
    assert "./ProvidersWorkbenchSections" in providers_source
    assert "./providers-workbench-model" in providers_source
    assert "./RemediationQueueFilters" in findings_view_source
    assert "./RemediationQueueFilterControls" in findings_filters_source
    assert "./FindingsDataTableColumns" in findings_table_source
    assert "./FindingsDataTableModel" in findings_table_columns_source
    assert "sort?: VpwDataTableSort" in vpw_data_table_source
    assert "VpwDataTableHeaderContent" in vpw_data_table_source
    assert "./FindingsDataTable" not in findings_model_source
    assert "./RemediationQueueStates" in findings_view_source
    assert "./RemediationQueueSummary" in findings_view_source
    assert "./RemediationQueueTableSection" in findings_view_source
    assert "EvidenceCenterRunContext" in reports_sections_source
    assert "EvidenceCenterTabs" in reports_source
    assert "ArtifactSection" in reports_tabs_source
    assert "EvidenceLifecycle" in reports_tabs_source
    assert "EvidenceCenterLifecycle" in reports_sections_source
    assert "EvidenceCenterHistory" in reports_sections_source
    assert "./EvidenceArtifactSection" in reports_lifecycle_source
    assert "./EvidenceLifecycleFlow" in reports_lifecycle_source
    assert "VpwEvidenceArtifactCard" not in reports_lifecycle_source
    assert "VpwEvidenceFlowCard" not in reports_lifecycle_source
    assert "ArtifactSection" in reports_artifact_section_source
    assert "RecommendedArtifactCard" in reports_artifact_section_source
    assert "EvidenceLifecycle" in reports_lifecycle_flow_source
    assert "VpwTimeline" in reports_lifecycle_flow_source
    assert "./EvidenceCenterHistoryColumns" in reports_history_source
    assert "./EvidenceCenterHistoryCells" in reports_history_columns_source
    assert "buildReportHistoryColumns" in reports_history_columns_source
    assert "ReportChecksumCell" in reports_history_cells_source
    assert "ReportArtifactCell" in reports_history_cells_source
    assert "ReportStatusCell" in reports_history_cells_source
    assert "ReportHistoryActionsCell" in reports_history_columns_source
    assert "VpwDataTableColumn" not in reports_history_source
    assert "EvidenceCenterManifest" in reports_sections_source
    assert "EvidenceCenterDecision" in reports_sections_source
    assert "ImportsHomeRoute" in imports_sections_source
    assert "NewImportRoute" in imports_sections_source
    assert "ImportRunDetailRoute" in imports_sections_source
    assert "ImportDiagnosticsDrawer" in imports_sections_source
    assert "./ImportDiagnosticsDrawerTabs" in imports_diagnostics_source
    assert "ImportDiagnosticsDrawerTabs" in imports_diagnostics_tabs_source
    assert "TabsContent" not in imports_diagnostics_source
    assert "ParserErrorsTable" in imports_diagnostics_tabs_source
    assert "CopyButton" in imports_diagnostics_tabs_source
    assert "SupportedFormatsRoute" in imports_sections_source
    assert "ImportsWorkbenchHistory" in imports_sections_source
    assert "./ImportsWorkbenchHistoryColumns" in imports_history_source
    assert "./ImportsWorkbenchHistoryActions" in imports_history_columns_source
    assert "buildImportHistoryColumns" in imports_history_columns_source
    assert "vpw-table-actions" not in imports_history_source
    assert "vpw-table-actions" not in imports_history_columns_source
    assert "ImportRunActions" in imports_history_actions_source
    assert "vpw-table-action-button" in imports_history_actions_source
    assert "ImportsWorkbenchHero" not in imports_sections_source
    assert "ImportsWorkbenchWizard" not in imports_sections_source
    assert "ImportsWorkbenchRunDetail" not in imports_sections_source
    assert "ImportsWorkbenchSupportedFormats" not in imports_sections_source
    for file_name in legacy_imports_all_in_one_files:
        assert not (REPO_ROOT / f"frontend/src/components/imports/{file_name}").exists()
    assert "ProjectsWorkbenchOverview" in projects_sections_source
    assert "./ProjectContext" in projects_overview_source
    assert "./ProjectMetrics" in projects_overview_source
    assert "ProjectContext" in projects_context_source
    assert "VpwToolbar" in projects_context_source
    assert "VpwCommandPanel" in projects_context_source
    assert "ProjectMetrics" in projects_metrics_source
    _assert_metric_strip_adapter(projects_metrics_source, "projects metric strip")
    assert "VpwMetricCard" not in projects_overview_source
    assert "ProjectsWorkbenchSetup" in projects_sections_source
    assert "ProjectsWorkbenchDirectory" in projects_sections_source
    assert "ProjectsWorkbenchActive" in projects_sections_source
    assert "./ProjectsWorkbenchActiveControls" in projects_active_source
    assert "ActiveProjectActions" in projects_active_controls_source
    assert "ActiveProjectEditForm" in projects_active_controls_source
    assert "ActiveProjectDeletePanel" in projects_active_controls_source
    assert "selectedProjectRouteSearch" not in projects_active_source
    assert "WaiversContext" in waivers_sections_source
    assert "VpwCommandPanel" in waivers_context_source
    _assert_metric_strip_adapter(waivers_context_source, "waivers metric strip")
    assert "WaiversWorkbenchCreate" in waivers_sections_source
    assert "WaiversWorkbenchRegister" in waivers_sections_source
    assert "WaiversWorkbenchReview" in waivers_sections_source
    assert "./WaiversWorkbenchCreateGuidance" in waivers_create_source
    assert "./WaiversWorkbenchForm" in waivers_create_source
    assert "WaiversWorkbenchCreateGuidance" in waivers_create_guidance_source
    assert "WaiverForm" in waivers_form_source
    assert "function WaiverForm" not in waivers_create_source
    assert "VpwKeyValueList" not in waivers_create_source
    assert "./waivers-register-model" in waivers_register_source
    assert "matchesWaiverSearch" in waivers_register_model_source
    assert "function matchesWaiverSearch" not in waivers_register_source
    assert "./waiver-form-model" in waivers_model_source
    assert "./waiver-lifecycle-model" in waivers_model_source
    assert "./waiver-scope-model" in waivers_model_source
    assert "./waiver-summary-model" in waivers_model_source
    assert "export function matchingFindings" not in waivers_model_source
    assert "export function statusTone" not in waivers_model_source
    assert "export function reviewQueue" not in waivers_model_source
    assert "export function waiverFormFromRecord" in waiver_form_model_source
    assert "export function matchingFindings" in waiver_scope_model_source
    assert "export function statusTone" in waiver_lifecycle_model_source
    assert "export function reviewQueue" in waiver_summary_model_source
    assert "SettingsContext" in settings_sections_source
    assert "VpwCommandPanel" in settings_context_source
    assert "SettingsWorkbenchOverview" in settings_sections_source
    assert "SettingsWorkbenchRuntime" in settings_sections_source
    assert "SettingsWorkbenchTokens" not in settings_sections_source
    assert not settings_tokens_path.exists()
    assert "ProvidersContext" in providers_sections_source
    assert "VpwCommandPanel" in providers_context_source
    assert "ProvidersWorkbenchMetrics" in providers_sections_source
    assert "ProviderDiagnosticsSection" in providers_sections_source
    assert "Runtime facts" in providers_diagnostics_source
    assert "Status check" in providers_diagnostics_source
    assert "ProviderUpdateJobPanel" in providers_update_job_source
    assert "ProviderRuntimeFactsPanel" in providers_runtime_facts_source
    assert "ProvidersWorkbenchSources" in providers_sections_source
    assert "./ProvidersWorkbenchSourcesColumns" in providers_sources_source
    assert "buildProviderSourceColumns" in providers_sources_columns_source
    assert "vpw-table-actions" not in providers_sources_source
    assert "vpw-table-action-button" in providers_sources_columns_source
    assert "ProvidersWorkbenchSnapshot" in providers_sections_source
    assert "ProvidersWorkbenchQuality" in providers_sections_source
    assert "./providers-workbench-source-model" in providers_model_source
    assert "./providers-workbench-status-model" in providers_model_source
    assert "./providers-workbench-types" in providers_model_source
    assert "sourceRows" in providers_source_model_source
    assert "providerSourceCounts" in providers_source_model_source
    assert "snapshotId" in providers_source_model_source
    assert "providerHealthTone" in providers_status_model_source
    assert "buildProviderEvidenceFlowItems" in providers_status_model_source
    assert "ProvidersWorkbenchProps" in providers_types_source
    assert "ProviderSourceRow" in providers_types_source
    assert len(reports_source.splitlines()) <= 240
    assert len(reports_sections_source.splitlines()) <= 40
    assert len(reports_run_context_source.splitlines()) <= 210
    assert len(reports_tabs_source.splitlines()) <= 260
    assert len(reports_lifecycle_source.splitlines()) <= 50
    assert len(reports_artifact_section_source.splitlines()) <= 280
    assert len(reports_lifecycle_flow_source.splitlines()) <= 150
    assert len(reports_history_source.splitlines()) <= 120
    assert len(reports_history_columns_source.splitlines()) <= 320
    assert len(reports_history_cells_source.splitlines()) <= 120
    assert len(reports_manifest_source.splitlines()) <= 150
    assert len(reports_decision_source.splitlines()) <= 330
    assert len(imports_source.splitlines()) <= 120
    assert len(imports_sections_source.splitlines()) <= 40
    assert len(imports_home_source.splitlines()) <= 220
    assert len(imports_new_source.splitlines()) <= 780
    assert len(imports_run_detail_source.splitlines()) <= 520
    assert len(imports_diagnostics_source.splitlines()) <= 120
    assert len(imports_diagnostics_tabs_source.splitlines()) <= 220
    assert len(imports_formats_source.splitlines()) <= 340
    assert len(imports_history_source.splitlines()) <= 120
    assert len(imports_history_columns_source.splitlines()) <= 180
    assert len(imports_history_actions_source.splitlines()) <= 100
    assert len(projects_source.splitlines()) <= 120
    assert len(projects_sections_source.splitlines()) <= 40
    assert len(projects_overview_source.splitlines()) <= 20
    assert len(projects_context_source.splitlines()) <= 90
    assert len(projects_metrics_source.splitlines()) <= 100
    assert len(projects_setup_source.splitlines()) <= 190
    assert len(projects_directory_source.splitlines()) <= 230
    assert len(projects_active_source.splitlines()) <= 180
    assert len(projects_active_controls_source.splitlines()) <= 180
    assert len(projects_model_source.splitlines()) <= 170
    assert len(waivers_source.splitlines()) <= 130
    assert len(waivers_sections_source.splitlines()) <= 40
    assert len(waivers_context_source.splitlines()) <= 190
    assert len(waivers_create_source.splitlines()) <= 80
    assert len(waivers_create_guidance_source.splitlines()) <= 90
    assert len(waivers_form_source.splitlines()) <= 330
    assert len(waivers_register_source.splitlines()) <= 290
    assert len(waivers_register_model_source.splitlines()) <= 130
    assert len(waivers_review_source.splitlines()) <= 200
    assert len(waivers_model_source.splitlines()) <= 140
    assert len(waiver_form_model_source.splitlines()) <= 80
    assert len(waiver_lifecycle_model_source.splitlines()) <= 90
    assert len(waiver_scope_model_source.splitlines()) <= 180
    assert len(waiver_summary_model_source.splitlines()) <= 180
    assert len(settings_source.splitlines()) <= 120
    assert len(settings_sections_source.splitlines()) <= 40
    assert len(settings_context_source.splitlines()) <= 110
    assert len(settings_overview_source.splitlines()) <= 220
    assert len(settings_runtime_source.splitlines()) <= 200
    assert len(settings_model_source.splitlines()) <= 220
    assert len(providers_source.splitlines()) <= 120
    assert len(providers_sections_source.splitlines()) <= 40
    assert len(providers_diagnostics_source.splitlines()) <= 240
    assert len(providers_update_job_source.splitlines()) <= 110
    assert len(providers_runtime_facts_source.splitlines()) <= 110
    assert len(providers_context_source.splitlines()) <= 230
    assert len(providers_metrics_source.splitlines()) <= 120
    assert len(providers_sources_source.splitlines()) <= 130
    assert len(providers_sources_columns_source.splitlines()) <= 120
    assert len(providers_snapshot_source.splitlines()) <= 230
    assert len(providers_quality_source.splitlines()) <= 190
    assert len(providers_model_source.splitlines()) <= 10
    assert len(providers_source_model_source.splitlines()) <= 240
    assert len(providers_status_model_source.splitlines()) <= 360
    assert len(providers_types_source.splitlines()) <= 60
    assert len(findings_source.splitlines()) <= 320
    assert len(findings_view_source.splitlines()) <= 240
    assert len(findings_filters_source.splitlines()) <= 290
    assert len(findings_filter_controls_source.splitlines()) <= 240
    assert len(findings_table_source.splitlines()) <= 100
    assert len(findings_table_columns_source.splitlines()) <= 300
    assert len(vpw_data_table_source.splitlines()) <= 200
    assert len(findings_table_model_source.splitlines()) <= 80
    assert len(findings_model_source.splitlines()) <= 280


def test_models_facade_reexports_focused_model_modules() -> None:
    imports = _imported_modules("src/vuln_prioritizer/models.py")

    assert "vuln_prioritizer.model_base" in imports
    assert "vuln_prioritizer.models_artifacts" in imports
    assert "vuln_prioritizer.models_attack" in imports
    assert "vuln_prioritizer.models_input" in imports
    assert "vuln_prioritizer.models_provider" in imports
    assert "vuln_prioritizer.models_remediation" in imports
    assert "vuln_prioritizer.models_waivers" in imports


def test_dependency_audit_requirements_include_dev_gate_tools() -> None:
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    package_names = {line.split(">", 1)[0].split("[", 1)[0] for line in requirements if line}
    audit_lock = (ROOT / "requirements.lock.txt").read_text(encoding="utf-8")
    runtime_lock = (ROOT / "requirements.runtime.lock.txt").read_text(encoding="utf-8")
    uv_lock = (REPO_ROOT / "uv.lock").read_text(encoding="utf-8")
    pinned_package_names = {
        match.group(1).replace("_", "-").lower()
        for match in re.finditer(r"^([A-Za-z0-9_.-]+)==", audit_lock, flags=re.MULTILINE)
    }
    runtime_pinned_package_names = {
        match.group(1).replace("_", "-").lower()
        for match in re.finditer(r"^([A-Za-z0-9_.-]+)==", runtime_lock, flags=re.MULTILINE)
    }

    assert {"mkdocs", "pytest-cov"}.issubset(package_names)
    assert "playwright" not in package_names
    assert {"rich", "typer"}.isdisjoint(package_names)
    assert all("==" not in line and "--hash" not in line for line in requirements)
    assert 'name = "vuln-prioritizer"' in uv_lock
    assert 'name = "vuln-prioritizer-workbench-workspace"' in uv_lock
    assert 'name = "pip-audit"' in uv_lock
    assert "autogenerated by uv" in audit_lock
    assert "--locked" in audit_lock
    assert "--hash=sha256:" in audit_lock
    assert {"mkdocs", "pip-audit", "pytest-cov"}.issubset(pinned_package_names)
    assert "backend/requirements.runtime.lock.txt" in runtime_lock
    assert "--python 3.12" in runtime_lock
    assert "--no-dev" in runtime_lock
    assert "--hash=sha256:" in runtime_lock
    assert {"fastapi", "psycopg", "uvicorn"}.issubset(runtime_pinned_package_names)
    assert {"rich", "typer"}.isdisjoint(runtime_pinned_package_names)
    assert "typer" not in pinned_package_names
    assert (
        not {
            "mkdocs",
            "mypy",
            "pip-audit",
            "pytest",
            "pytest-cov",
            "ruff",
            "twine",
        }
        & runtime_pinned_package_names
    )


def test_sdist_manifest_excludes_partial_test_tree() -> None:
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")

    assert "prune tests" in manifest


def test_backend_package_boundary_intentionally_ships_workbench_app() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    package_check = (ROOT.parent / "scripts" / "check_package_contents.py").read_text(
        encoding="utf-8"
    )
    makefile = (ROOT.parent / "Makefile").read_text(encoding="utf-8")

    assert 'include = ["vuln_prioritizer*", "app*"]' in pyproject
    assert "[project.scripts]" not in pyproject
    assert "app/main.py" in package_check
    assert '"vuln_prioritizer/cli.py"' in package_check
    assert "FORBIDDEN_WHEEL_PREFIXES" in package_check
    assert "FORBIDDEN_WHEEL_FILES" in package_check
    assert "vuln_prioritizer/api/" in package_check
    assert "vuln_prioritizer/commands/" in package_check
    assert "vuln_prioritizer/db/" in package_check
    assert "vuln_prioritizer/reporting_" in package_check
    assert "vuln_prioritizer/web/" in package_check
    assert "package-contents-check: package" in makefile
    assert "package-check: package-contents-check" in makefile
    assert "pipx-source-smoke" not in makefile


def test_import_execution_is_split_into_stage_services_with_guardrails() -> None:
    source = (ROOT / "app/services/import_execution.py").read_text(encoding="utf-8")
    context_source = (ROOT / "app/services/import_execution_context.py").read_text(encoding="utf-8")
    failure_source = (ROOT / "app/services/import_execution_failures.py").read_text(
        encoding="utf-8"
    )
    parse_failure_source = (ROOT / "app/services/import_execution_parse_failures.py").read_text(
        encoding="utf-8"
    )
    upload_source = (ROOT / "app/services/import_execution_uploads.py").read_text(encoding="utf-8")
    upload_prepare_source = (ROOT / "app/services/import_execution_upload_prepare.py").read_text(
        encoding="utf-8"
    )
    upload_storage_source = (ROOT / "app/services/import_execution_upload_storage.py").read_text(
        encoding="utf-8"
    )
    run_state_source = (ROOT / "app/services/import_execution_run_state.py").read_text(
        encoding="utf-8"
    )
    dedup_source = (ROOT / "app/services/import_execution_dedup.py").read_text(encoding="utf-8")
    persistence_source = (ROOT / "app/services/import_execution_persistence.py").read_text(
        encoding="utf-8"
    )
    persistence_bulk_source = (
        ROOT / "app/services/import_execution_persistence_bulk.py"
    ).read_text(encoding="utf-8")
    persistence_payloads_source = (
        ROOT / "app/services/import_execution_persistence_payloads.py"
    ).read_text(encoding="utf-8")
    persistence_attack_source = (
        ROOT / "app/services/import_execution_persistence_attack.py"
    ).read_text(encoding="utf-8")
    persistence_queries_source = (
        ROOT / "app/services/import_execution_persistence_queries.py"
    ).read_text(encoding="utf-8")
    summary_source = (ROOT / "app/services/import_execution_summary.py").read_text(encoding="utf-8")

    assert "def execute_project_import_upload" in source
    assert "app.services.import_execution_context" in source
    assert "app.services.import_execution_failures" in source
    assert "app.services.import_execution_parse_failures" in source
    assert "app.services.import_execution_uploads" in source
    assert "app.services.import_execution_persistence" in source
    assert "app.services.import_execution_summary" in source
    assert "app.services.import_execution_dedup" in persistence_source
    assert "def _apply_workbench_asset_context" in context_source
    assert "def _apply_workbench_vex" in context_source
    assert "def _parse_error_payload" in context_source
    assert "def raise_analysis_failure" in failure_source
    assert "def raise_parse_failure" in parse_failure_source
    assert "def raise_sidecar_parse_failure" in parse_failure_source
    assert "app.services.import_execution_upload_prepare" in upload_source
    assert "app.services.import_execution_upload_storage" in upload_source
    assert "app.services.import_execution_run_state" in upload_source
    assert "def prepare_import_upload" in upload_prepare_source
    assert "def initial_upload_summary" in upload_prepare_source
    assert "def store_prepared_uploads" in upload_storage_source
    assert "def apply_stored_upload_summaries" in run_state_source
    assert "def mark_import_run_running" in run_state_source
    assert "def _dedup_key_parts" in dedup_source
    assert "def _finding_dedup_key" in dedup_source
    assert "def _dedup_key_parts" not in persistence_source
    assert "def _persist_workbench_occurrences" in persistence_source
    assert "def _persist_workbench_occurrences_bulk_insert" not in persistence_source
    assert "def _persist_workbench_occurrences_bulk_insert" in persistence_bulk_source
    assert "def _decision_payload_for_occurrence" not in persistence_source
    assert "def _decision_payload_for_occurrence" in persistence_payloads_source
    assert "def _persist_workbench_finding_attack_context" in persistence_attack_source
    assert "def _existing_findings_by_dedup_key" in persistence_queries_source
    assert "def _job_payload" in summary_source
    assert "def _record_import_audit" in summary_source
    assert len(source.splitlines()) <= 320
    assert len(context_source.splitlines()) <= 220
    assert len(failure_source.splitlines()) <= 140
    assert len(parse_failure_source.splitlines()) <= 240
    assert len(upload_source.splitlines()) <= 40
    assert len(upload_prepare_source.splitlines()) <= 280
    assert len(upload_storage_source.splitlines()) <= 120
    assert len(run_state_source.splitlines()) <= 200
    assert len(persistence_source.splitlines()) <= 320
    assert len(persistence_bulk_source.splitlines()) <= 340
    assert len(persistence_payloads_source.splitlines()) <= 320
    assert len(persistence_attack_source.splitlines()) <= 180
    assert len(persistence_queries_source.splitlines()) <= 120
    assert len(summary_source.splitlines()) <= 100
