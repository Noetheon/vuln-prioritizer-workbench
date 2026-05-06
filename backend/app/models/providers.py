"""Provider status DTOs for the Workbench API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict
from sqlmodel import Field, SQLModel


class ProviderSourceStatusPublic(SQLModel):
    """Status for one provider source within the latest stored snapshot."""

    name: str
    selected: bool = False
    available: bool = False
    stale: bool = False
    value: str | None = None
    last_sync: str | None = None
    last_error: str | None = None
    cache_age_seconds: int | None = None
    detail: str | None = None


class ProviderSnapshotStatusPublic(SQLModel):
    """Stable status projection for the latest provider snapshot."""

    id: str | None = None
    created_at: str | None = None
    content_hash: str | None = None
    nvd_last_sync: str | None = None
    epss_date: str | None = None
    kev_catalog_version: str | None = None
    generated_at: str | None = None
    selected_sources: list[str] = Field(default_factory=list)
    requested_cves: int = 0
    source_hashes: dict[str, Any] = Field(default_factory=dict)
    source_metadata: dict[str, Any] = Field(default_factory=dict)
    source_path: str | None = None
    locked_provider_data: bool = False
    missing: bool = True
    mode: str = "missing"


class ProviderUpdateJobCreate(BaseModel):
    """Request body for a deterministic provider update job."""

    sources: list[str] = Field(default_factory=lambda: ["nvd", "epss", "kev"])
    cve_ids: list[str] = Field(default_factory=list)
    max_cves: int | None = Field(default=None, ge=1, le=10000)
    cache_only: bool = True


class ProviderUpdateJobPublic(BaseModel):
    """Provider update-job status record."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    status: str
    execution_mode: str = "request"
    requested_sources: list[str] = Field(default_factory=list)
    started_at: str | None = None
    finished_at: str | None = None
    error_message: str | None = None
    metadata_: dict[str, Any] = Field(default_factory=dict, alias="metadata")


class ProviderUpdateJobsPublic(BaseModel):
    """Provider update-job collection response."""

    data: list[ProviderUpdateJobPublic] = Field(default_factory=list)
    count: int


class ProviderStatusPublic(SQLModel):
    """Provider status response for the Workbench backend shell."""

    status: str
    snapshot: ProviderSnapshotStatusPublic
    sources: list[ProviderSourceStatusPublic] = Field(default_factory=list)
    latest_update_job: ProviderUpdateJobPublic | None = None
    cache_dir: str | None = None
    snapshot_dir: str | None = None
    warnings: list[str] = Field(default_factory=list)
    last_sync: str | None = None
    last_error: str | None = None
    cache_age_seconds: int | None = None
    snapshot_mode: str


ProviderSourceStatus = ProviderSourceStatusPublic
ProviderSnapshotStatus = ProviderSnapshotStatusPublic
ProviderStatusResponse = ProviderStatusPublic
