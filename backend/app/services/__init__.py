"""Template Workbench service layer."""

from app.services.analysis import AnalysisService, TemplateAnalysisError, TemplateAnalysisResult
from app.services.attack import build_project_attack_summary_payload
from app.services.decisions import (
    DecisionDataUnavailableError,
    build_cvss_only_comparison_payload,
    build_finding_explanation_payload,
    build_project_summary_payload,
)
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
    verify_evidence_bundle_zip,
)

__all__ = [
    "AnalysisService",
    "DecisionDataUnavailableError",
    "MarkdownProviderSnapshot",
    "MarkdownReportFinding",
    "MarkdownReportPayload",
    "ReportGenerationError",
    "ReportVerificationError",
    "ReportService",
    "TemplateAnalysisError",
    "TemplateAnalysisResult",
    "build_project_attack_summary_payload",
    "build_cvss_only_comparison_payload",
    "build_finding_explanation_payload",
    "build_project_summary_payload",
    "render_analysis_result_json",
    "render_evidence_bundle_zip",
    "render_findings_csv",
    "render_html_executive_report",
    "render_markdown_report",
    "verify_evidence_bundle_zip",
]
