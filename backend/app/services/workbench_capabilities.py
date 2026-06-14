"""Workbench runtime capability catalog and public projection."""

from __future__ import annotations

from app.core.config import Settings
from app.domain.engine.options import AttackSource, InputFormat
from app.models.reports import REPORT_FORMAT_VALUES, ReportFormat
from app.models.workbench import (
    AttackSourceCapabilityPublic,
    ImportFormatCapabilityPublic,
    ReportFormatCapabilityPublic,
    SidecarUploadCapabilityPublic,
    UploadPolicyPublic,
    WorkbenchCapabilitiesPublic,
)
from app.services.report_contracts import (
    REPORT_CONTENT_TYPE_CSV,
    REPORT_CONTENT_TYPE_HTML,
    REPORT_CONTENT_TYPE_JSON,
    REPORT_CONTENT_TYPE_MARKDOWN,
    REPORT_CONTENT_TYPE_SARIF,
    REPORT_CONTENT_TYPE_ZIP,
    REPORT_FILENAME_ANALYSIS_JSON,
    REPORT_FILENAME_ATTACK_NAVIGATOR,
    REPORT_FILENAME_EVIDENCE_BUNDLE,
    REPORT_FILENAME_EXECUTIVE_HTML,
    REPORT_FILENAME_FINDINGS_CSV,
    REPORT_FILENAME_SARIF_RESULTS,
    REPORT_FILENAME_TECHNICAL_MARKDOWN,
    REPORT_KIND_ANALYSIS_JSON,
    REPORT_KIND_ATTACK_NAVIGATOR,
    REPORT_KIND_EVIDENCE_BUNDLE,
    REPORT_KIND_EXECUTIVE_HTML,
    REPORT_KIND_FINDINGS_CSV,
    REPORT_KIND_SARIF_RESULTS,
    REPORT_KIND_TECHNICAL_MARKDOWN,
)

IMPORT_REQUEST_OVERHEAD_BYTES = 64 * 1024

FORMAT_CATEGORY_LABELS = {
    "simple": "Simple inputs",
    "scanner": "Scanner exports",
    "sbom": "SBOM / dependency data",
    "network": "Network scanner exports",
}

IMPORT_FORMAT_CAPABILITIES: tuple[ImportFormatCapabilityPublic, ...] = (
    ImportFormatCapabilityPublic(
        input_type=InputFormat.cve_list.value,
        label="CVE list",
        category="simple",
        category_label=FORMAT_CATEGORY_LABELS["simple"],
        extensions=[".txt", ".csv"],
        accepted_mime_types=["text/plain", "text/csv", "application/vnd.ms-excel"],
        best_for="Quick lists of already-known CVEs.",
        expected_shape="Plain text or CSV with one CVE identifier per line.",
        minimum_fields=["One CVE identifier per line or a CVE column"],
        optional_fields=[],
        context_support="cve-only",
        example_snippet="CVE-2024-3094\nCVE-2023-4863",
        notes=["Use this for quick supplied CVE lists without asset context."],
        short_description="Plain text or CSV with one CVE identifier per line.",
    ),
    ImportFormatCapabilityPublic(
        input_type=InputFormat.generic_occurrence_csv.value,
        label="Generic occurrence CSV",
        category="simple",
        category_label=FORMAT_CATEGORY_LABELS["simple"],
        extensions=[".csv"],
        accepted_mime_types=["text/csv", "text/plain", "application/vnd.ms-excel"],
        best_for="Manual vulnerability backlog or occurrence lists.",
        expected_shape="CSV with CVE identifiers and optional asset or component context.",
        minimum_fields=["cve_id or equivalent supported CVE field"],
        optional_fields=[
            "component_name",
            "component_version",
            "purl",
            "owner",
            "service",
            "environment",
            "fix_version",
        ],
        context_support="asset-context-capable",
        example_snippet=(
            "cve_id,component_name,component_version,owner,service\n"
            "CVE-2024-3094,xz,5.6.0,platform,payments"
        ),
        notes=["Asset context can improve prioritization and explanations."],
        short_description="CSV with CVE identifiers and optional asset or component context.",
    ),
    ImportFormatCapabilityPublic(
        input_type=InputFormat.trivy_json.value,
        label="Trivy JSON",
        category="scanner",
        category_label=FORMAT_CATEGORY_LABELS["scanner"],
        extensions=[".json"],
        accepted_mime_types=["application/json", "text/json"],
        best_for="Container and filesystem exports from Trivy.",
        expected_shape="Trivy vulnerability report JSON.",
        minimum_fields=["Results[].Vulnerabilities[]"],
        optional_fields=["PkgName", "InstalledVersion", "FixedVersion", "Severity"],
        context_support="component-context",
        example_snippet=('{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-3094"}]}]}'),
        notes=["Use the JSON report exported by Trivy."],
        short_description="Trivy vulnerability export.",
    ),
    ImportFormatCapabilityPublic(
        input_type=InputFormat.grype_json.value,
        label="Grype JSON",
        category="scanner",
        category_label=FORMAT_CATEGORY_LABELS["scanner"],
        extensions=[".json"],
        accepted_mime_types=["application/json", "text/json"],
        best_for="Container and SBOM exports from Grype.",
        expected_shape="Grype vulnerability report JSON.",
        minimum_fields=["matches[] vulnerability data"],
        optional_fields=["artifact", "fix", "matchDetails"],
        context_support="component-context",
        example_snippet='{"matches":[{"vulnerability":{"id":"CVE-2024-3094"}}]}',
        notes=["Use the JSON report exported by Grype."],
        short_description="Grype vulnerability export.",
    ),
    ImportFormatCapabilityPublic(
        input_type=InputFormat.cyclonedx_json.value,
        label="CycloneDX SBOM JSON",
        category="sbom",
        category_label=FORMAT_CATEGORY_LABELS["sbom"],
        extensions=[".json"],
        accepted_mime_types=["application/json", "text/json"],
        best_for="Software inventory with vulnerability references.",
        expected_shape="CycloneDX JSON with vulnerability records.",
        minimum_fields=["vulnerabilities[].id"],
        optional_fields=["components[].bom-ref", "components[].purl", "affects", "ratings"],
        context_support="component-vulnerability-context",
        example_snippet=(
            '{"bomFormat":"CycloneDX","components":[],"vulnerabilities":[{"id":"CVE-2024-3094"}]}'
        ),
        notes=["Plain SBOM-only BOM without vulnerabilities is not sufficient."],
        short_description="CycloneDX SBOM plus vulnerabilities.",
    ),
    ImportFormatCapabilityPublic(
        input_type=InputFormat.spdx_json.value,
        label="SPDX SBOM JSON",
        category="sbom",
        category_label=FORMAT_CATEGORY_LABELS["sbom"],
        extensions=[".json"],
        accepted_mime_types=["application/json", "text/json"],
        best_for="SPDX package inventory with vulnerability references.",
        expected_shape="SPDX JSON with vulnerability records.",
        minimum_fields=["vulnerabilities[].id"],
        optional_fields=["packages[].SPDXID", "externalRefs", "affects", "severity"],
        context_support="component-context",
        example_snippet=(
            '{"spdxVersion":"SPDX-2.3","packages":[],"vulnerabilities":[{"id":"CVE-2024-3094"}]}'
        ),
        notes=["SPDX vulnerability records are required to create prioritized occurrences."],
        short_description="SPDX JSON plus vulnerabilities.",
    ),
    ImportFormatCapabilityPublic(
        input_type=InputFormat.dependency_check_json.value,
        label="Dependency-Check JSON",
        category="scanner",
        category_label=FORMAT_CATEGORY_LABELS["scanner"],
        extensions=[".json"],
        accepted_mime_types=["application/json", "text/json"],
        best_for="OWASP Dependency-Check output.",
        expected_shape="OWASP Dependency-Check JSON report.",
        minimum_fields=["dependencies[].vulnerabilities[].name"],
        optional_fields=["fileName", "filePath", "projectReferences", "severity"],
        context_support="component-context",
        example_snippet=('{"dependencies":[{"vulnerabilities":[{"name":"CVE-2024-3094"}]}]}'),
        notes=[
            "Use the JSON report exported by OWASP Dependency-Check.",
            "Current normalization preserves file name, file path, "
            "first project reference, and raw severity.",
        ],
        short_description="OWASP Dependency-Check JSON report.",
    ),
    ImportFormatCapabilityPublic(
        input_type=InputFormat.github_alerts_json.value,
        label="GitHub alerts JSON",
        category="scanner",
        category_label=FORMAT_CATEGORY_LABELS["scanner"],
        extensions=[".json"],
        accepted_mime_types=["application/json", "text/json"],
        best_for="Pinned GitHub security or dependency alert evidence.",
        expected_shape="Pinned GitHub alert export shape.",
        minimum_fields=["alert vulnerability records"],
        optional_fields=["dependency", "security_vulnerability", "security_advisory"],
        context_support="component-context",
        example_snippet=(
            '[{"security_vulnerability":{"vulnerable_version_range":"< 1.0.0"},'
            '"security_advisory":{"cve_id":"CVE-2024-3094"}}]'
        ),
        notes=["Use the pinned JSON export shape supported by the backend."],
        short_description="Pinned GitHub alert JSON export shape.",
    ),
    ImportFormatCapabilityPublic(
        input_type=InputFormat.nessus_xml.value,
        label="Nessus XML",
        category="network",
        category_label=FORMAT_CATEGORY_LABELS["network"],
        extensions=[".nessus", ".xml"],
        accepted_mime_types=["application/xml", "text/xml"],
        best_for="Network tool export evidence supplied as local XML.",
        expected_shape="Nessus export with ReportHost / ReportItem CVE data.",
        minimum_fields=["ReportHost", "ReportItem CVE data"],
        optional_fields=["risk_factor", "severity", "svc_name", "port", "protocol"],
        context_support="partial-occurrence-context",
        example_snippet=(
            '<NessusClientData_v2><Report><ReportHost name="host"><ReportItem>'
            "<cve>CVE-2024-3094</cve></ReportItem></ReportHost></Report></NessusClientData_v2>"
        ),
        notes=["Parsed locally from supplied exports; the Workbench does not scan networks."],
        short_description="Nessus XML export parsed locally.",
    ),
    ImportFormatCapabilityPublic(
        input_type=InputFormat.openvas_xml.value,
        label="OpenVAS XML",
        category="network",
        category_label=FORMAT_CATEGORY_LABELS["network"],
        extensions=[".xml"],
        accepted_mime_types=["application/xml", "text/xml"],
        best_for="OpenVAS-style result evidence supplied as local XML.",
        expected_shape="OpenVAS result CVE data.",
        minimum_fields=["result CVE data"],
        optional_fields=["host", "hostname", "ip", "severity", "threat", "nvt refs"],
        context_support="partial-occurrence-context",
        example_snippet=(
            "<report><results><result><nvt><cve>CVE-2024-3094</cve></nvt>"
            "</result></results></report>"
        ),
        notes=["Parsed locally from supplied exports; the Workbench does not scan networks."],
        short_description="OpenVAS XML export parsed locally.",
    ),
)

SIDE_CAR_UPLOAD_CAPABILITIES: tuple[SidecarUploadCapabilityPublic, ...] = (
    SidecarUploadCapabilityPublic(
        id="asset-context",
        label="Asset context CSV",
        form_field="asset_context_file",
        extensions=[".csv"],
        accepted_mime_types=["text/csv", "text/plain", "application/vnd.ms-excel"],
        description="Optional CSV overlay with asset owner, service, exposure, and criticality.",
    ),
    SidecarUploadCapabilityPublic(
        id="vex",
        label="VEX JSON",
        form_field="vex_file",
        extensions=[".json"],
        accepted_mime_types=["application/json", "text/json"],
        description="Optional VEX/OpenVEX statements used to suppress or annotate findings.",
    ),
)

ATTACK_SOURCE_CAPABILITIES: tuple[AttackSourceCapabilityPublic, ...] = (
    AttackSourceCapabilityPublic(
        value=AttackSource.none.value,
        label="No ATT&CK mapping",
        detail="Do not enrich this import with ATT&CK mappings.",
    ),
    AttackSourceCapabilityPublic(
        value=AttackSource.ctid_json.value,
        label="CTID JSON",
        detail="Use a reviewed CTID JSON mapping file from the managed artifact directory.",
        requires_mapping_file=True,
        supports_technique_metadata_file=True,
    ),
    AttackSourceCapabilityPublic(
        value=AttackSource.local_curated.value,
        label="Local curated",
        detail="Use a reviewed local curated mapping file from the managed artifact directory.",
        requires_mapping_file=True,
        supports_technique_metadata_file=True,
    ),
)


def supported_import_input_types() -> tuple[str, ...]:
    """Return the active Workbench import input types in UI order."""
    return tuple(item.input_type for item in IMPORT_FORMAT_CAPABILITIES)


def default_import_suffix_by_input_type() -> dict[str, str]:
    """Return the default temporary file suffix used for parser adapters."""
    return {
        item.input_type: item.extensions[0]
        for item in IMPORT_FORMAT_CAPABILITIES
        if item.extensions
    }


def allowed_upload_suffixes() -> dict[str, set[str]]:
    """Return upload suffix validation data keyed by input type."""
    return {item.input_type: set(item.extensions) for item in IMPORT_FORMAT_CAPABILITIES}


def allowed_upload_mime_hints() -> dict[str, set[str]]:
    """Return upload MIME hint validation data keyed by input type."""
    return {item.input_type: set(item.accepted_mime_types) for item in IMPORT_FORMAT_CAPABILITIES}


def build_workbench_capabilities(settings: Settings) -> WorkbenchCapabilitiesPublic:
    """Build the public capability contract for the active runtime settings."""
    return WorkbenchCapabilitiesPublic(
        import_formats=[item.model_copy(deep=True) for item in IMPORT_FORMAT_CAPABILITIES],
        report_formats=[_report_format_capability(value) for value in REPORT_FORMAT_VALUES],
        upload_policy=UploadPolicyPublic(
            max_upload_bytes=settings.max_upload_bytes,
            max_request_body_bytes=settings.max_request_body_bytes,
            import_request_overhead_bytes=IMPORT_REQUEST_OVERHEAD_BYTES,
        ),
        sidecar_uploads=[item.model_copy(deep=True) for item in SIDE_CAR_UPLOAD_CAPABILITIES],
        attack_sources=[item.model_copy(deep=True) for item in ATTACK_SOURCE_CAPABILITIES],
    )


def _report_format_capability(report_format: ReportFormat) -> ReportFormatCapabilityPublic:
    report_formats: dict[ReportFormat, ReportFormatCapabilityPublic] = {
        "markdown": ReportFormatCapabilityPublic(
            format="markdown",
            label="Markdown",
            title="Technical Markdown Report",
            action_label="Generate Markdown",
            detail="Technical report for analyst handoff, pull requests, and audit notes.",
            audience="Engineering",
            kind=REPORT_KIND_TECHNICAL_MARKDOWN,
            filename=REPORT_FILENAME_TECHNICAL_MARKDOWN,
            content_type=REPORT_CONTENT_TYPE_MARKDOWN,
        ),
        "html": ReportFormatCapabilityPublic(
            format="html",
            label="HTML",
            title="Executive HTML Report",
            action_label="Generate executive HTML",
            detail=(
                "Executive browser report with priority summary, evidence links, "
                "and safe rendering."
            ),
            audience="CISO",
            kind=REPORT_KIND_EXECUTIVE_HTML,
            filename=REPORT_FILENAME_EXECUTIVE_HTML,
            content_type=REPORT_CONTENT_TYPE_HTML,
        ),
        "json": ReportFormatCapabilityPublic(
            format="json",
            label="JSON",
            title="JSON Findings Export",
            action_label="Export analysis JSON",
            detail=(
                "Machine-readable findings and analysis data for automation and downstream systems."
            ),
            audience="Automation",
            kind=REPORT_KIND_ANALYSIS_JSON,
            filename=REPORT_FILENAME_ANALYSIS_JSON,
            content_type=REPORT_CONTENT_TYPE_JSON,
        ),
        "csv": ReportFormatCapabilityPublic(
            format="csv",
            label="CSV",
            title="CSV Findings Export",
            action_label="Export CSV findings",
            detail=(
                "Spreadsheet-friendly findings table for triage, filtering, and stakeholder review."
            ),
            audience="Audit",
            kind=REPORT_KIND_FINDINGS_CSV,
            filename=REPORT_FILENAME_FINDINGS_CSV,
            content_type=REPORT_CONTENT_TYPE_CSV,
        ),
        "zip": ReportFormatCapabilityPublic(
            format="zip",
            label="Evidence ZIP",
            title="Evidence ZIP Bundle",
            action_label="Build evidence ZIP",
            detail=(
                "ZIP package with reports, manifest, provider snapshot, source input hash "
                "metadata, and SHA256 checksums."
            ),
            audience="Audit",
            kind=REPORT_KIND_EVIDENCE_BUNDLE,
            filename=REPORT_FILENAME_EVIDENCE_BUNDLE,
            content_type=REPORT_CONTENT_TYPE_ZIP,
        ),
        "attack-navigator": ReportFormatCapabilityPublic(
            format="attack-navigator",
            label="ATT&CK Navigator",
            title="ATT&CK Navigator Layer",
            action_label="Export Navigator",
            detail="Defensive ATT&CK Navigator JSON when mapped techniques are available.",
            audience="Security engineering",
            kind=REPORT_KIND_ATTACK_NAVIGATOR,
            filename=REPORT_FILENAME_ATTACK_NAVIGATOR,
            content_type=REPORT_CONTENT_TYPE_JSON,
        ),
        "sarif": ReportFormatCapabilityPublic(
            format="sarif",
            label="SARIF",
            title="SARIF Export",
            action_label="Export SARIF",
            detail=(
                "SARIF 2.1.0 results for GitHub code scanning and CI security evidence workflows."
            ),
            audience="CI",
            kind=REPORT_KIND_SARIF_RESULTS,
            filename=REPORT_FILENAME_SARIF_RESULTS,
            content_type=REPORT_CONTENT_TYPE_SARIF,
        ),
    }
    return report_formats[report_format].model_copy(deep=True)
