"""Shared Workbench and analysis option enums."""

from __future__ import annotations

from enum import StrEnum


class OutputFormat(StrEnum):
    """Data representation and logic for Output Format."""

    markdown = "markdown"
    json = "json"
    sarif = "sarif"
    table = "table"


class PriorityFilter(StrEnum):
    """Data representation and logic for Priority Filter."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class SortBy(StrEnum):
    """Data representation and logic for Sort By."""

    priority = "priority"
    operational = "operational"
    epss = "epss"
    cvss = "cvss"
    cve = "cve"


class AttackSource(StrEnum):
    """Data representation and logic for Attack Source."""

    none = "none"
    local_csv = "local-csv"
    local_curated = "local-curated"
    ctid_json = "ctid-json"


class InputFormat(StrEnum):
    """Data representation and logic for Input Format."""

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


PRIORITY_LABELS = {
    PriorityFilter.critical: "Critical",
    PriorityFilter.high: "High",
    PriorityFilter.medium: "Medium",
    PriorityFilter.low: "Low",
}
