"""State command response models."""

from __future__ import annotations

from pydantic import Field

from vuln_prioritizer.model_base import StrictModel


class StateInitMetadata(StrictModel):
    schema_version: str = "1.2.0"
    generated_at: str
    db_path: str


class StateInitSummary(StrictModel):
    initialized: bool = True
    snapshot_count: int = 0


class StateInitReport(StrictModel):
    metadata: StateInitMetadata
    summary: StateInitSummary = Field(default_factory=StateInitSummary)


class StateImportMetadata(StrictModel):
    schema_version: str = "1.2.0"
    generated_at: str
    db_path: str
    input_path: str


class StateImportSummary(StrictModel):
    imported: bool = True
    snapshot_id: int | None = None
    snapshot_generated_at: str | None = None
    finding_count: int = 0
    snapshot_count: int = 0


class StateImportReport(StrictModel):
    metadata: StateImportMetadata
    summary: StateImportSummary = Field(default_factory=StateImportSummary)


class StateHistoryMetadata(StrictModel):
    schema_version: str = "1.2.0"
    generated_at: str
    db_path: str
    cve_id: str
    entry_count: int = 0


class StateHistoryEntry(StrictModel):
    snapshot_generated_at: str
    snapshot_path: str
    input_path: str | None = None
    priority_label: str
    priority_rank: int
    in_kev: bool = False
    waived: bool = False
    waiver_status: str | None = None
    waiver_owner: str | None = None
    services: list[str] = Field(default_factory=list)
    asset_ids: list[str] = Field(default_factory=list)


class StateHistoryReport(StrictModel):
    metadata: StateHistoryMetadata
    items: list[StateHistoryEntry] = Field(default_factory=list)


class StateWaiverMetadata(StrictModel):
    schema_version: str = "1.2.0"
    generated_at: str
    db_path: str
    status_filter: str = "all"
    latest_only: bool = True
    entry_count: int = 0


class StateWaiverEntry(StrictModel):
    snapshot_generated_at: str
    snapshot_path: str
    cve_id: str
    priority_label: str
    waiver_status: str
    waiver_owner: str | None = None
    waiver_expires_on: str | None = None
    waiver_review_on: str | None = None
    waiver_days_remaining: int | None = None


class StateWaiverReport(StrictModel):
    metadata: StateWaiverMetadata
    items: list[StateWaiverEntry] = Field(default_factory=list)


class StateTopServicesMetadata(StrictModel):
    schema_version: str = "1.2.0"
    generated_at: str
    db_path: str
    days: int
    priority_filter: str = "all"
    limit: int = 10
    latest_only: bool = False
    entry_count: int = 0


class StateTopServiceEntry(StrictModel):
    service: str
    occurrence_count: int = 0
    distinct_cves: int = 0
    snapshot_count: int = 0
    kev_count: int = 0
    latest_seen: str | None = None


class StateTopServicesReport(StrictModel):
    metadata: StateTopServicesMetadata
    items: list[StateTopServiceEntry] = Field(default_factory=list)


class StateTrendsMetadata(StrictModel):
    schema_version: str = "1.2.0"
    generated_at: str
    db_path: str
    days: int
    priority_filter: str = "all"
    entry_count: int = 0


class StateTrendEntry(StrictModel):
    snapshot_generated_at: str
    snapshot_path: str
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    kev_count: int = 0
    attack_mapped_count: int = 0
    waived_count: int = 0


class StateTrendsReport(StrictModel):
    metadata: StateTrendsMetadata
    items: list[StateTrendEntry] = Field(default_factory=list)


class StateServiceHistoryMetadata(StrictModel):
    schema_version: str = "1.2.0"
    generated_at: str
    db_path: str
    service: str
    days: int
    priority_filter: str = "all"
    entry_count: int = 0


class StateServiceHistoryEntry(StrictModel):
    snapshot_generated_at: str
    snapshot_path: str
    occurrence_count: int = 0
    distinct_cves: int = 0
    critical_count: int = 0
    high_count: int = 0
    kev_count: int = 0
    waived_count: int = 0
    cve_ids: list[str] = Field(default_factory=list)


class StateServiceHistoryReport(StrictModel):
    metadata: StateServiceHistoryMetadata
    items: list[StateServiceHistoryEntry] = Field(default_factory=list)
