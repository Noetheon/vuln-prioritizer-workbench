"""Shared command option enums independent of the CLI adapter layer."""

from __future__ import annotations

from enum import StrEnum


class OutputFormat(StrEnum):
    markdown = "markdown"
    json = "json"
    sarif = "sarif"
    table = "table"


class ReportOutputFormat(StrEnum):
    markdown = "markdown"
    json = "json"
    table = "table"


class TableJsonOutputFormat(StrEnum):
    table = "table"
    json = "json"


class SnapshotCreateOutputFormat(StrEnum):
    json = "json"
    markdown = "markdown"


FULL_OUTPUT_FORMATS = (
    OutputFormat.markdown,
    OutputFormat.json,
    OutputFormat.sarif,
    OutputFormat.table,
)
REPORT_OUTPUT_FORMATS = (
    ReportOutputFormat.markdown,
    ReportOutputFormat.json,
    ReportOutputFormat.table,
)
TABLE_AND_JSON_OUTPUT_FORMATS = (
    TableJsonOutputFormat.table,
    TableJsonOutputFormat.json,
)
SNAPSHOT_CREATE_OUTPUT_FORMATS = (
    SnapshotCreateOutputFormat.json,
    SnapshotCreateOutputFormat.markdown,
)


class PriorityFilter(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class SortBy(StrEnum):
    priority = "priority"
    operational = "operational"
    epss = "epss"
    cvss = "cvss"
    cve = "cve"


class AttackSource(StrEnum):
    none = "none"
    local_csv = "local-csv"
    ctid_json = "ctid-json"


class InputFormat(StrEnum):
    auto = "auto"
    cve_list = "cve-list"
    generic_occurrence_csv = "generic-occurrence-csv"
    trivy_json = "trivy-json"
    grype_json = "grype-json"
    cyclonedx_json = "cyclonedx-json"
    spdx_json = "spdx-json"
    dependency_check_json = "dependency-check-json"
    github_alerts_json = "github-alerts-json"
    nessus_xml = "nessus-xml"
    openvas_xml = "openvas-xml"


class PolicyProfile(StrEnum):
    default = "default"
    enterprise = "enterprise"
    conservative = "conservative"


class DataSourceName(StrEnum):
    all = "all"
    nvd = "nvd"
    epss = "epss"
    kev = "kev"


class TargetKind(StrEnum):
    generic = "generic"
    image = "image"
    repository = "repository"
    filesystem = "filesystem"
    host = "host"


class RollupBy(StrEnum):
    asset = "asset"
    service = "service"
    owner = "owner"
    exposure = "exposure"
    environment = "environment"
    component = "component"


class StateWaiverStatusFilter(StrEnum):
    all = "all"
    active = "active"
    review_due = "review_due"
    expired = "expired"


class StatePriorityScope(StrEnum):
    all = "all"
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class SummaryTemplate(StrEnum):
    detailed = "detailed"
    compact = "compact"


PRIORITY_LABELS = {
    PriorityFilter.critical: "Critical",
    PriorityFilter.high: "High",
    PriorityFilter.medium: "Medium",
    PriorityFilter.low: "Low",
}
