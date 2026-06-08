"""Workbench status and local demo workspace DTOs."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from sqlmodel import Field, SQLModel

from app.models.projects import ProjectPublic
from app.models.reports import ReportPublic
from app.models.runs import AnalysisRunPublic


class WorkbenchStatus(SQLModel):
    """Status response returned by the active Workbench runtime."""

    schema_version: Literal["workbench-status.v1"] = "workbench-status.v1"
    status: str
    app: str
    core_package: str
    core_version: str
    environment: str
    runtime_mode: str
    database_status: str
    schema_status: str
    demo_workspace_enabled: bool
    alembic_head: str
    worker_status: Literal["ready", "not_ready", "unknown"]
    worker_last_seen_at: datetime | None = None
    api_docs_enabled: bool
    api_docs_path: str | None = None


class WorkbenchHealth(SQLModel):
    """Minimal local health response."""

    status: str


class ImportFormatCapabilityPublic(SQLModel):
    """Supported import format metadata published by the Workbench runtime."""

    input_type: str
    label: str
    category: str
    category_label: str
    extensions: list[str] = Field(default_factory=list)
    accepted_mime_types: list[str] = Field(default_factory=list)
    best_for: str
    expected_shape: str
    minimum_fields: list[str] = Field(default_factory=list)
    optional_fields: list[str] = Field(default_factory=list)
    context_support: str
    example_snippet: str
    notes: list[str] = Field(default_factory=list)
    short_description: str


class SidecarUploadCapabilityPublic(SQLModel):
    """Supported optional import sidecar metadata."""

    id: str
    label: str
    form_field: str
    extensions: list[str] = Field(default_factory=list)
    accepted_mime_types: list[str] = Field(default_factory=list)
    required: bool = False
    description: str


class AttackSourceCapabilityPublic(SQLModel):
    """Supported ATT&CK import source metadata."""

    value: str
    label: str
    detail: str
    requires_mapping_file: bool = False
    supports_technique_metadata_file: bool = False


class ReportFormatCapabilityPublic(SQLModel):
    """Supported report artifact metadata published by the Workbench runtime."""

    format: str
    label: str
    title: str
    action_label: str
    detail: str
    audience: str
    kind: str
    filename: str
    content_type: str


class UploadPolicyPublic(SQLModel):
    """Upload and request limits enforced by the active Workbench runtime."""

    max_upload_bytes: int
    max_request_body_bytes: int
    import_request_overhead_bytes: int


class WorkbenchCapabilitiesPublic(SQLModel):
    """Versioned Workbench capability contract for browser/runtime alignment."""

    schema_version: Literal["workbench-capabilities.v1"] = "workbench-capabilities.v1"
    import_formats: list[ImportFormatCapabilityPublic] = Field(default_factory=list)
    report_formats: list[ReportFormatCapabilityPublic] = Field(default_factory=list)
    upload_policy: UploadPolicyPublic
    sidecar_uploads: list[SidecarUploadCapabilityPublic] = Field(default_factory=list)
    attack_sources: list[AttackSourceCapabilityPublic] = Field(default_factory=list)


class DemoWorkspaceCreate(SQLModel):
    """Request payload for creating or resetting the local demo workspace."""

    reset: bool = False


class DemoWorkspaceStatusPublic(SQLModel):
    """Status for the optional local demo workspace."""

    enabled: bool
    seeded: bool = False
    project_id: uuid.UUID | None = None
    project_name: str | None = None
    latest_run_id: uuid.UUID | None = None
    finding_count: int = 0
    asset_count: int = 0
    report_count: int = 0
    waiver_count: int = 0
    message: str | None = None


class DemoWorkspacePublic(DemoWorkspaceStatusPublic):
    """Materialized local demo workspace response."""

    project: ProjectPublic
    latest_run: AnalysisRunPublic
    reports: list[ReportPublic] = Field(default_factory=list)
