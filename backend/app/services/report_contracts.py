"""Stable report artifact contract constants for the Workbench."""

from __future__ import annotations

from vuln_prioritizer.workbench_report_contracts import CSV_FINDINGS_COLUMNS as CSV_FINDINGS_COLUMNS

REPORT_KIND_TECHNICAL_MARKDOWN = "technical-markdown"
REPORT_KIND_EXECUTIVE_HTML = "executive-html"
REPORT_KIND_ANALYSIS_JSON = "analysis-result-json"
REPORT_KIND_FINDINGS_CSV = "findings-csv"
REPORT_KIND_EVIDENCE_BUNDLE = "evidence-bundle"
REPORT_KIND_ATTACK_NAVIGATOR = "attack-navigator-layer"
REPORT_KIND_SARIF_RESULTS = "sarif-results"
REPORT_KIND_GOVERNANCE_ROLLUPS = "governance-rollups"
REPORT_KIND_GOVERNANCE_WAIVERS = "governance-waivers"
REPORT_KIND_GOVERNANCE_VEX = "governance-vex-summary"
REPORT_KIND_GOVERNANCE_ASSET_CONTEXT = "governance-asset-context"
REPORT_KIND_GOVERNANCE_DETECTION_COVERAGE = "governance-detection-coverage"

REPORT_FILENAME_TECHNICAL_MARKDOWN = "technical-report.md"
REPORT_FILENAME_EXECUTIVE_HTML = "executive-report.html"
REPORT_FILENAME_ANALYSIS_JSON = "analysis-result.v1.json"
REPORT_FILENAME_FINDINGS_CSV = "findings.csv"
REPORT_FILENAME_EVIDENCE_BUNDLE = "evidence-bundle.zip"
REPORT_FILENAME_ATTACK_NAVIGATOR = "attack-navigator-layer.json"
REPORT_FILENAME_SARIF_RESULTS = "results.sarif"
REPORT_FILENAME_GOVERNANCE_ROLLUPS = "governance/rollups.json"
REPORT_FILENAME_GOVERNANCE_WAIVERS = "governance/waivers.json"
REPORT_FILENAME_GOVERNANCE_VEX = "governance/vex-summary.json"
REPORT_FILENAME_GOVERNANCE_ASSET_CONTEXT = "governance/asset-context.json"
REPORT_FILENAME_GOVERNANCE_DETECTION_COVERAGE = "governance/detection-coverage.json"

REPORT_CONTENT_TYPE_MARKDOWN = "text/markdown; charset=utf-8"
REPORT_CONTENT_TYPE_HTML = "text/html; charset=utf-8"
REPORT_CONTENT_TYPE_JSON = "application/json; charset=utf-8"
REPORT_CONTENT_TYPE_CSV = "text/csv; charset=utf-8"
REPORT_CONTENT_TYPE_SARIF = "application/sarif+json; charset=utf-8"
REPORT_CONTENT_TYPE_ZIP = "application/zip"

ANALYSIS_RESULT_SCHEMA = "analysis-result.v1"
ANALYSIS_RESULT_SCHEMA_VERSION = "1.0.0"
EVIDENCE_BUNDLE_MANIFEST_SCHEMA_VERSION = "1.1.0"
DETERMINISTIC_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
DETERMINISTIC_ZIP_FILE_MODE = 0o644 << 16
PRIORITY_LABELS = ("Critical", "High", "Medium", "Low")
MARKDOWN_SPECIAL_CHARS = "\\`*_{}[]()!"

SECRET_REDACTION_KEYS = (
    "api_key",
    "authorization",
    "cookie",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
)
LOCAL_PATH_REDACTION_KEYS = (
    "input_path",
    "path",
    "provider_snapshot_file",
    "source_path",
    "upload_path",
)
