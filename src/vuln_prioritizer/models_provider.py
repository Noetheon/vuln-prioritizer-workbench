"""Provider response and diagnostics models."""

from __future__ import annotations

from pydantic import Field

from vuln_prioritizer.model_base import StrictModel


class NvdData(StrictModel):
    cve_id: str
    description: str | None = None
    cvss_base_score: float | None = None
    cvss_severity: str | None = None
    cvss_version: str | None = None
    cvss_vector: str | None = None
    vulnerability_status: str | None = None
    published: str | None = None
    last_modified: str | None = None
    cwes: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    reference_tags: dict[str, list[str]] = Field(default_factory=dict)


class EpssData(StrictModel):
    cve_id: str
    epss: float | None = None
    percentile: float | None = None
    date: str | None = None


class KevData(StrictModel):
    cve_id: str
    in_kev: bool = False
    vendor_project: str | None = None
    product: str | None = None
    short_description: str | None = None
    date_added: str | None = None
    required_action: str | None = None
    due_date: str | None = None
    known_ransomware_campaign_use: str | None = None
    notes: str | None = None


class DefensiveContext(StrictModel):
    cve_id: str
    source: str
    source_id: str | None = None
    title: str | None = None
    summary: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    ssvc_decision: str | None = None
    exploitation: str | None = None
    automatable: str | None = None
    technical_impact: str | None = None
    published: str | None = None
    modified: str | None = None
    url: str | None = None
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class ProviderEvidence(StrictModel):
    nvd: NvdData
    epss: EpssData
    kev: KevData
    defensive_contexts: list[DefensiveContext] = Field(default_factory=list)


class ProviderLookupDiagnostics(StrictModel):
    requested: int = 0
    cache_hits: int = 0
    network_fetches: int = 0
    failures: int = 0
    content_hits: int = 0
    empty_records: int = 0
    stale_cache_hits: int = 0
    degraded: bool = False
