"""Report payload models and report service errors."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class ReportGenerationError(RuntimeError):
    """Raised when a report cannot be generated from the stored run."""


class ReportVerificationError(RuntimeError):
    """Raised when an evidence bundle cannot be verified."""


@dataclass(frozen=True, slots=True)
class MarkdownProviderSnapshot:
    """Provider snapshot context shown in generated Markdown reports."""

    id: str | None
    content_hash: str | None
    nvd_last_sync: str | None
    epss_date: str | None
    kev_catalog_version: str | None
    created_at: str | None = None
    source_hashes: dict[str, Any] = field(default_factory=dict)
    source_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class MarkdownReportFinding:
    """Finding context shown in generated Markdown reports."""

    operational_rank: int
    cve_id: str
    priority: str
    status: str
    risk_score: float | None
    epss: float | None
    cvss_base_score: float | None
    in_kev: bool
    asset: str | None
    component: str | None
    rationale: str | None
    recommended_action: str | None
    data_quality_confidence: str | None
    id: str | None = None
    dedup_key: str | None = None
    priority_rank: int | None = None
    asset_key: str | None = None
    owner: str | None = None
    business_service: str | None = None
    environment: str | None = None
    exposure: str | None = None
    criticality: str | None = None
    component_purl: str | None = None
    attack_mapped: bool = False
    suppressed_by_vex: bool = False
    under_investigation: bool = False
    waived: bool = False
    decision_statement: str | None = None
    business_impact: str | None = None
    decision_sla: str | None = None
    data_quality_flags: list[str] = field(default_factory=list)
    vulnerability: dict[str, Any] = field(default_factory=dict)
    explanation: dict[str, Any] = field(default_factory=dict)
    data_quality: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    occurrences: list[dict[str, Any]] = field(default_factory=list)
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class MarkdownReportPayload:
    """Pure rendering payload for deterministic snapshot tests."""

    generated_at: datetime
    project_id: str
    project_name: str
    run_id: str
    run_status: str
    input_type: str
    filename: str | None
    summary: dict[str, Any]
    findings: list[MarkdownReportFinding]
    provider_snapshot: MarkdownProviderSnapshot | None
    governance_rollups: dict[str, Any] = field(default_factory=dict)
    detection_coverage: dict[str, Any] = field(default_factory=dict)
    project_description: str | None = None
    project_owner_id: str | None = None
    project_created_at: datetime | None = None
    project_updated_at: datetime | None = None
    run_started_at: datetime | None = None
    run_finished_at: datetime | None = None
    run_error: str | None = None
    run_errors: dict[str, Any] = field(default_factory=dict)
