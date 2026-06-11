"""Workbench service layer."""

from app.services.analysis import (
    AnalysisService,
    WorkbenchAnalysisError,
    WorkbenchAnalysisResult,
)
from app.services.attack import (
    ATTACK_NAVIGATOR_FILTERS,
    build_attack_navigator_layer_payload,
    build_project_attack_summary_payload,
    build_project_attack_summary_payload_from_rows,
)
from app.services.dashboard import (
    build_project_dashboard_payload,
    build_project_dashboard_payload_from_repositories,
    dashboard_signal_counts,
)
from app.services.decisions import (
    DecisionDataUnavailableError,
    build_cvss_only_comparison_payload,
    build_finding_explanation_payload,
    build_project_summary_payload,
    build_project_summary_payload_from_counts,
)
from app.services.github_issues import (
    GitHubIssueCreationError,
    build_github_issue_preview_items,
    create_github_issue,
    github_export_token,
    github_repository_path,
)
from app.services.governance import build_project_governance_rollups_payload_from_repositories
from app.services.governance_rollups import build_project_governance_rollups_payload
from app.services.reports import (
    MarkdownProviderSnapshot,
    MarkdownReportFinding,
    MarkdownReportPayload,
    ReportGenerationError,
    ReportService,
    ReportVerificationError,
    render_analysis_result_json,
    render_evidence_bundle_zip,
    render_findings_csv,
    render_html_executive_report,
    render_markdown_report,
    render_sarif_report,
    verify_evidence_bundle_zip,
)
from app.services.risk_insights import (
    build_project_risk_insights_payload,
    build_project_risk_insights_payload_from_repositories,
)

__all__ = [
    "AnalysisService",
    "DecisionDataUnavailableError",
    "GitHubIssueCreationError",
    "MarkdownProviderSnapshot",
    "MarkdownReportFinding",
    "MarkdownReportPayload",
    "ReportGenerationError",
    "ReportVerificationError",
    "ReportService",
    "WorkbenchAnalysisError",
    "WorkbenchAnalysisResult",
    "ATTACK_NAVIGATOR_FILTERS",
    "build_attack_navigator_layer_payload",
    "build_project_attack_summary_payload",
    "build_project_attack_summary_payload_from_rows",
    "build_cvss_only_comparison_payload",
    "build_project_dashboard_payload",
    "build_project_dashboard_payload_from_repositories",
    "build_finding_explanation_payload",
    "build_github_issue_preview_items",
    "build_project_governance_rollups_payload",
    "build_project_governance_rollups_payload_from_repositories",
    "build_project_risk_insights_payload",
    "build_project_risk_insights_payload_from_repositories",
    "build_project_summary_payload",
    "build_project_summary_payload_from_counts",
    "dashboard_signal_counts",
    "create_github_issue",
    "github_export_token",
    "github_repository_path",
    "render_analysis_result_json",
    "render_evidence_bundle_zip",
    "render_findings_csv",
    "render_html_executive_report",
    "render_markdown_report",
    "render_sarif_report",
    "verify_evidence_bundle_zip",
]
