from __future__ import annotations

import ast

from utils.hygiene import (
    ROOT,
    _imported_modules,
    _module_name,
    _normalized_internal_imports,
    _python_module_paths,
)


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

    assert "app.services.import_execution" in route_imports
    assert "AnalysisService" not in route_source
    assert "build_importer_registry" not in route_source
    assert "RunRepository" not in route_source
    assert "def execute_project_import_upload" in service_source
    assert "AnalysisService" in service_source
    assert "app.services.import_execution_parsing" in service_source
    assert "build_importer_registry" in parsing_source


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
    report_contract_test_root = ROOT / "tests/api/report_contracts"
    report_contract_test_sources = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(report_contract_test_root.glob("test_*.py"))
    }
    api_reports_test_source = "\n".join(report_contract_test_sources.values())

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
    assert "import vuln_prioritizer.workbench_report_contracts" in contracts_source
    assert "CSV_FINDINGS_COLUMNS = _workbench_report_contracts.CSV_FINDINGS_COLUMNS" in (
        contracts_source
    )
    assert not (ROOT / "tests/api/test_workbench_reports_api.py").exists()
    assert {
        "test_evidence_bundle_contracts.py",
        "test_report_api_contracts.py",
        "test_report_format_contracts.py",
        "test_report_snapshot_contracts.py",
    }.issubset(report_contract_test_sources)
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
    assert "EXECUTIVE_REPORT_CSS = " not in renderers_source
    assert "def render_markdown_report" in markdown_source
    assert "app.services.report_markdown_sections" in markdown_imports
    assert "def _markdown_governance_section" not in markdown_source
    assert "def _markdown_governance_section" in markdown_sections_source
    assert "def _markdown_detection_coverage_section" in markdown_sections_source
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


def test_run_workflow_metadata_uses_versioned_contract_projection() -> None:
    contract_source = (ROOT / "app/contracts/run_workflow.py").read_text(encoding="utf-8")
    metadata_source = (ROOT / "app/services/run_workflow_metadata.py").read_text(encoding="utf-8")
    projection_source = (ROOT / "app/services/run_workflow_projection.py").read_text(
        encoding="utf-8"
    )
    model_source = (ROOT / "app/models/runs.py").read_text(encoding="utf-8")
    run_route_imports = _imported_modules("app/api/routes/runs.py")
    import_route_imports = _imported_modules("app/api/routes/imports.py")
    writer_paths = (
        "app/services/import_execution.py",
        "app/services/import_execution_run_state.py",
        "app/services/import_execution_failures.py",
        "app/services/import_execution_parse_failures.py",
        "app/services/import_background.py",
        "app/services/provider_updates.py",
    )

    assert "RUN_WORKFLOW_SUMMARY_SCHEMA_VERSION" in contract_source
    assert "class RunWorkflowSummaryV1" in contract_source
    assert "class RunWorkflowErrorV1" in contract_source
    assert "def workflow_public_fields" in contract_source
    assert "app.contracts.run_workflow" in model_source
    assert "app.services.run_workflow_projection" in run_route_imports
    assert "app.services.run_workflow_projection" in import_route_imports
    assert "def public_workflow_fields" in metadata_source
    assert "workflow_public_fields(summary, error)" in metadata_source
    assert "public_workflow_fields(run)" in projection_source
    assert "AnalysisRunPublic(" in projection_source
    assert "AnalysisRunSummaryPublic(" in projection_source
    for path in writer_paths:
        source = (ROOT / path).read_text(encoding="utf-8")
        assert (
            "merge_summary_payload" in source
            or "update_workflow_summary" in source
            or "set_workflow_summary" in source
        ), path
    for path in (
        "app/services/import_execution_failures.py",
        "app/services/import_execution_parse_failures.py",
        "app/services/import_background.py",
        "app/services/provider_updates.py",
    ):
        source = (ROOT / path).read_text(encoding="utf-8")
        assert "merge_error_payload" in source or "set_workflow_error" in source, path


def test_run_workflow_raw_metadata_access_stays_behind_service_boundary() -> None:
    allowed = {
        "app/models/runs.py",
        "app/repositories/runs.py",
        "app/services/run_workflow_metadata.py",
    }
    offenders: list[str] = []
    for path in sorted((ROOT / "app").rglob("*.py")):
        relative = str(path.relative_to(ROOT))
        if relative.startswith("app/alembic/") or relative in allowed:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {"summary_json", "error_json"}:
                if isinstance(node.value, ast.Name) and node.value.id == "analysis_result":
                    continue
                offenders.append(f"{relative}:{node.lineno}:{node.attr}")

    assert offenders == []


def test_run_workflow_contract_suites_do_not_read_raw_db_metadata() -> None:
    suite_roots = (
        ROOT / "tests/api/import_contracts",
        ROOT / "tests/api/report_contracts",
        ROOT / "tests/api/workflow_contracts",
    )
    offenders: list[str] = []
    for suite_root in suite_roots:
        for path in sorted(suite_root.rglob("*.py")):
            relative = str(path.relative_to(ROOT))
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr in {"summary_json", "error_json"}:
                    offenders.append(f"{relative}:{node.lineno}:{node.attr}")

    assert offenders == []


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

    assert _python_module_paths("inputs/parsers")


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


def test_models_facade_reexports_focused_model_modules() -> None:
    imports = _imported_modules("src/vuln_prioritizer/models.py")

    assert "vuln_prioritizer.model_base" in imports
    assert "vuln_prioritizer.models_artifacts" in imports
    assert "vuln_prioritizer.models_attack" in imports
    assert "vuln_prioritizer.models_input" in imports
    assert "vuln_prioritizer.models_provider" in imports
    assert "vuln_prioritizer.models_remediation" in imports
    assert "vuln_prioritizer.models_waivers" in imports


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
