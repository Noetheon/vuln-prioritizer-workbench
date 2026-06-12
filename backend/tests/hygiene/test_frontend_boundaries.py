from __future__ import annotations

from utils.hygiene import REPO_ROOT, _assert_metric_strip_adapter


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
    for filename, symbol in expected_slices.items():
        source = (vpw_root / filename).read_text(encoding="utf-8")
        assert symbol in source


def test_semantic_badge_model_is_split_behind_facade() -> None:
    vpw_root = REPO_ROOT / "frontend/src/components/vpw"
    facade_source = (vpw_root / "semantic-badge-model.ts").read_text(encoding="utf-8")
    expected_slices = {
        "semantic-badge-types.ts": "export function normalizeSemanticToken",
        "semantic-risk-model.ts": "export function normalizeRiskLevel",
        "semantic-signal-model.ts": "export function normalizeSignalKind",
        "semantic-status-model.ts": "export function normalizeStatus",
    }

    assert "normalizeSemanticToken" not in facade_source
    assert "function normalizeRiskLevel" not in facade_source
    for filename, symbol in expected_slices.items():
        source = (vpw_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".ts") in facade_source


def test_workbench_components_are_split_behind_design_system_facade() -> None:
    vpw_root = REPO_ROOT / "frontend/src/components/vpw"
    facade_source = (vpw_root / "WorkbenchComponents.tsx").read_text(encoding="utf-8")
    expected_slices = {
        "WorkbenchBadges.tsx": "export function StatusBadge",
        "WorkbenchDetail.tsx": "export function DetailDrawer",
        "WorkbenchFeedback.tsx": "export function Callout",
        "WorkbenchSurface.tsx": "export function DataTableFrame",
    }

    assert "export function DetailDrawer" not in facade_source
    assert "export function DataTableFrame" not in facade_source
    for filename, symbol in expected_slices.items():
        source = (vpw_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".tsx") in facade_source
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
    assert 'from "./ImportsRouteContainer"' in imports_route_source
    assert "ImportsService" not in imports_route_source
    assert "useMutation" not in imports_route_source
    assert "useWorkbenchContext" not in imports_route_source
    assert "ImportsService" in imports_container_source
    assert "useMutation" in imports_container_source
    assert "useWorkbenchContext" in imports_container_source


def test_run_workflow_components_use_typed_contract_fields() -> None:
    roots = (REPO_ROOT / "frontend/src", REPO_ROOT / "frontend/tests")
    banned_fields = ("summary_json", "error_json", "raw_summary", "raw_error")
    offenders: dict[str, list[str]] = {field: [] for field in banned_fields}

    for root in roots:
        paths = sorted(root.rglob("*"))
        for path in paths:
            if path.suffix not in {".ts", ".tsx"} or "src/client" in path.as_posix():
                continue
            source = path.read_text(encoding="utf-8")
            relative = path.relative_to(REPO_ROOT).as_posix()
            for field in banned_fields:
                if field in source:
                    offenders[field].append(relative)

    assert offenders == {field: [] for field in banned_fields}


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
    assert "imports-workbench-model" in timeline_source
    assert "export function importRunTimelineItems" in timeline_source
    assert "export function objectRecord" in records_source
    assert "export function stringValue" in records_source
    assert "function hasProviderEvidence" in timeline_source
    assert "function hasProviderEvidence" not in model_source


def test_import_format_metadata_is_split_by_contract_surface() -> None:
    lib_root = REPO_ROOT / "frontend/src/lib"
    facade_source = (lib_root / "import-format-metadata.ts").read_text(encoding="utf-8")
    expected_slices = {
        "import-format-catalog.ts": "export function supportedImportFormats",
        "import-format-types.ts": 'ImportFormatCapabilityPublic["input_type"]',
        "import-parser-preview.ts": "export async function buildParserPreview",
        "import-readiness.ts": "export function buildImportReadinessChecks",
    }

    assert "SUPPORTED_IMPORT_FORMATS" not in facade_source
    assert "export async function buildParserPreview" not in facade_source
    assert "export function buildImportReadinessChecks" not in facade_source
    for filename, symbol in expected_slices.items():
        source = (lib_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".ts") in facade_source


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

    for filename, symbol in expected_wizard_slices.items():
        source = (imports_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".tsx") in wizard_facade

    route_source = (imports_root / "NewImportRoute.tsx").read_text(encoding="utf-8")
    assert "./NewImportWizardFooter" in route_source
    assert "./NewImportFailurePanel" in route_source
    assert "function WizardFooter" not in route_source
    assert "function ImportFailurePanel" not in route_source

    for filename, symbol in expected_wizard_support_slices.items():
        source = (imports_root / filename).read_text(encoding="utf-8")
        assert symbol in source

    source_option = (imports_root / "NewImportSourceOption.tsx").read_text(encoding="utf-8")
    source_glyph = (imports_root / "NewImportSourceGlyph.tsx").read_text(encoding="utf-8")
    assert "./NewImportSourceGlyph" in source_option
    assert "./NewImportSourceGlyphIcons" in source_glyph
    assert "function ImportSourceGlyph" not in source_option
    assert "function ImportSourceGlyph" in source_glyph
    upload_source = (imports_root / "NewImportUploadStep.tsx").read_text(encoding="utf-8")
    assert "./NewImportUploadPreview" in upload_source
    assert "function ParserPreviewPanel" not in upload_source

    for filename, symbol in expected_run_detail_slices.items():
        source = (imports_root / filename).read_text(encoding="utf-8")
        assert symbol in source

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


def test_supported_formats_route_is_split_from_detail_and_filter_surfaces() -> None:
    imports_root = REPO_ROOT / "frontend/src/components/imports"
    route_source = (imports_root / "SupportedFormatsRoute.tsx").read_text(encoding="utf-8")
    expected_slices = {
        "SupportedFormatsColumns.tsx": "export function buildSupportedFormatColumns",
        "SupportedFormatDetailPanel.tsx": "export function SupportedFormatDetailPanel",
        "SupportedFormatsFilters.tsx": "export function SupportedFormatsFilters",
        "supported-formats-route-model.ts": "export function filterSupportedFormats",
    }

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
    assert "WhyDialog" not in all_findings_sources


def test_dashboard_and_finding_detail_use_vpw_surfaces() -> None:
    dashboard_paths = [
        REPO_ROOT / "frontend/src/components/dashboard/RiskOperationsDashboard.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardContextBar.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardContextActions.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardContextProjectPicker.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardProviderWarning.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardRemediationSection.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/dashboard-summary-model.ts",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardMetricStrip.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardDetailRail.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardOperationsStatePanel.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardRecentRunsPanel.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardDataQualityPanel.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardRecommendedActionsPanel.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardRemediationColumns.tsx",
        REPO_ROOT / "frontend/src/components/dashboard/DashboardRiskReductionPanel.tsx",
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
    dashboard_summary_source = dashboard_paths[6].read_text(encoding="utf-8")
    dashboard_metric_strip_source = dashboard_paths[7].read_text(encoding="utf-8")
    dashboard_detail_rail_source = dashboard_paths[8].read_text(encoding="utf-8")
    dashboard_operations_source = dashboard_paths[9].read_text(encoding="utf-8")
    dashboard_recent_runs_source = dashboard_paths[10].read_text(encoding="utf-8")
    dashboard_data_quality_source = dashboard_paths[11].read_text(encoding="utf-8")
    dashboard_recommended_actions_source = dashboard_paths[12].read_text(encoding="utf-8")
    dashboard_remediation_columns_source = dashboard_paths[13].read_text(encoding="utf-8")
    dashboard_risk_posture_source = dashboard_paths[14].read_text(encoding="utf-8")
    finding_context_source = finding_detail_paths[1].read_text(encoding="utf-8")
    assert "DashboardProviderWarning" in dashboard_source
    assert "DashboardContextBar" in dashboard_source
    assert "DashboardMetricStrip" in dashboard_source
    assert "DashboardRiskReductionPanel" in dashboard_source
    assert "DashboardDetailRail" not in dashboard_source
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
    _assert_metric_strip_adapter(
        dashboard_metric_strip_source,
        "dashboard metric strip",
    )
    assert "VpwSurface" in dashboard_paths[4].read_text(encoding="utf-8")
    assert "VpwSurface" in dashboard_paths[5].read_text(encoding="utf-8")
    assert "VpwDataTable" in dashboard_paths[5].read_text(encoding="utf-8")
    _assert_metric_strip_adapter(
        dashboard_paths[7].read_text(encoding="utf-8"),
        "dashboard route metric strip",
    )
    assert "VpwSurface" in dashboard_operations_source
    assert "VpwSurface" in dashboard_recent_runs_source
    assert "VpwSurface" in dashboard_data_quality_source
    assert "VpwSurface" in dashboard_recommended_actions_source
    assert "VpwSurface" in dashboard_risk_posture_source
    assert "buildRiskPostureProjection" in dashboard_risk_posture_source
    assert "selectedRiskPostureReducers" in dashboard_risk_posture_source
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

    for filename, symbol in expected_top_slices.items():
        source = (model_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".ts") in facade_source
    for filename, symbol in expected_evidence_slices.items():
        source = (model_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".ts") in evidence_facade_source


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

    for filename, symbol in expected_findings_slices.items():
        source = (findings_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".ts") in findings_facade

    for filename, symbol in expected_asset_slices.items():
        source = (asset_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".ts") in asset_facade


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
    assert "export function AssetLinkedFindingsContent" not in linked_facade_source
    for filename, symbol in expected_linked_slices.items():
        source = (asset_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".tsx") in linked_facade_source


def test_asset_context_forms_are_split_by_view_surface() -> None:
    asset_root = REPO_ROOT / "frontend/src/components/assets"
    facade_source = (asset_root / "AssetContextForm.tsx").read_text(encoding="utf-8")
    expected_slices = {
        "AssetContextForms.tsx": "export function AssetContextForms",
        "AssetContextImportForm.tsx": "export function AssetContextImportForm",
        "AssetForm.tsx": "export function AssetForm",
    }

    assert "export function AssetForm" not in facade_source
    for filename, symbol in expected_slices.items():
        source = (asset_root / filename).read_text(encoding="utf-8")
        assert symbol in source
        assert filename.removesuffix(".tsx") in facade_source


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


def test_workbench_frontend_feature_containers_delegate_to_sections() -> None:
    reports_source = (REPO_ROOT / "frontend/src/components/reports/EvidenceCenter.tsx").read_text(
        encoding="utf-8"
    )
    reports_sections_source = (
        REPO_ROOT / "frontend/src/components/reports/EvidenceCenterSections.tsx"
    ).read_text(encoding="utf-8")
    (REPO_ROOT / "frontend/src/components/reports/EvidenceCenterRunContext.tsx").read_text(
        encoding="utf-8"
    )
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
    (REPO_ROOT / "frontend/src/components/reports/EvidenceCenterManifest.tsx").read_text(
        encoding="utf-8"
    )
    (REPO_ROOT / "frontend/src/components/reports/EvidenceCenterDecision.tsx").read_text(
        encoding="utf-8"
    )
    imports_source = (REPO_ROOT / "frontend/src/components/imports/ImportsWorkbench.tsx").read_text(
        encoding="utf-8"
    )
    imports_sections_source = (
        REPO_ROOT / "frontend/src/components/imports/ImportsWorkbenchSections.tsx"
    ).read_text(encoding="utf-8")
    (REPO_ROOT / "frontend/src/components/imports/ImportsHomeRoute.tsx").read_text(encoding="utf-8")
    (REPO_ROOT / "frontend/src/components/imports/NewImportRoute.tsx").read_text(encoding="utf-8")
    (REPO_ROOT / "frontend/src/components/imports/ImportRunDetailRoute.tsx").read_text(
        encoding="utf-8"
    )
    imports_diagnostics_source = (
        REPO_ROOT / "frontend/src/components/imports/ImportDiagnosticsDrawer.tsx"
    ).read_text(encoding="utf-8")
    imports_diagnostics_tabs_source = (
        REPO_ROOT / "frontend/src/components/imports/ImportDiagnosticsDrawerTabs.tsx"
    ).read_text(encoding="utf-8")
    (REPO_ROOT / "frontend/src/components/imports/SupportedFormatsRoute.tsx").read_text(
        encoding="utf-8"
    )
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
    (REPO_ROOT / "frontend/src/components/findings/FindingsDataTableModel.ts").read_text(
        encoding="utf-8"
    )
    findings_model_source = (
        REPO_ROOT / "frontend/src/components/findings/remediation-queue-model.ts"
    ).read_text(encoding="utf-8")
    findings_view_source = (
        REPO_ROOT / "frontend/src/components/findings/RemediationQueueView.tsx"
    ).read_text(encoding="utf-8")
    findings_filters_source = (
        REPO_ROOT / "frontend/src/components/findings/RemediationQueueFilters.tsx"
    ).read_text(encoding="utf-8")
    (REPO_ROOT / "frontend/src/components/findings/RemediationQueueFilterControls.tsx").read_text(
        encoding="utf-8"
    )
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
    (REPO_ROOT / "frontend/src/components/projects/ProjectsWorkbenchSetup.tsx").read_text(
        encoding="utf-8"
    )
    (REPO_ROOT / "frontend/src/components/projects/ProjectsWorkbenchDirectory.tsx").read_text(
        encoding="utf-8"
    )
    projects_active_source = (
        REPO_ROOT / "frontend/src/components/projects/ProjectsWorkbenchActive.tsx"
    ).read_text(encoding="utf-8")
    projects_active_controls_source = (
        REPO_ROOT / "frontend/src/components/projects/ProjectsWorkbenchActiveControls.tsx"
    ).read_text(encoding="utf-8")
    (REPO_ROOT / "frontend/src/components/projects/projects-workbench-model.ts").read_text(
        encoding="utf-8"
    )
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
    (REPO_ROOT / "frontend/src/components/waivers/WaiversWorkbenchReview.tsx").read_text(
        encoding="utf-8"
    )
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
    (REPO_ROOT / "frontend/src/components/settings/SettingsWorkbenchOverview.tsx").read_text(
        encoding="utf-8"
    )
    settings_tokens_path = (
        REPO_ROOT / "frontend/src/components/settings/SettingsWorkbenchTokens.tsx"
    )
    (REPO_ROOT / "frontend/src/components/settings/SettingsWorkbenchRuntime.tsx").read_text(
        encoding="utf-8"
    )
    (REPO_ROOT / "frontend/src/components/settings/settings-workbench-model.ts").read_text(
        encoding="utf-8"
    )
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
    (REPO_ROOT / "frontend/src/components/providers/ProvidersWorkbenchMetrics.tsx").read_text(
        encoding="utf-8"
    )
    providers_sources_source = (
        REPO_ROOT / "frontend/src/components/providers/ProvidersWorkbenchSources.tsx"
    ).read_text(encoding="utf-8")
    providers_sources_columns_source = (
        REPO_ROOT / "frontend/src/components/providers/ProvidersWorkbenchSourcesColumns.tsx"
    ).read_text(encoding="utf-8")
    (REPO_ROOT / "frontend/src/components/providers/ProvidersWorkbenchSnapshot.tsx").read_text(
        encoding="utf-8"
    )
    (REPO_ROOT / "frontend/src/components/providers/ProvidersWorkbenchQuality.tsx").read_text(
        encoding="utf-8"
    )
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
