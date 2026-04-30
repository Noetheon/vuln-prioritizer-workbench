"""GitHub issue export models for the template Workbench API."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Literal

from pydantic import field_validator
from sqlalchemy import Column, DateTime, Index, Integer, String, UniqueConstraint
from sqlmodel import Field, SQLModel

from app.models.base import get_datetime_utc
from app.models.enums import FindingPriority

GITHUB_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GITHUB_LABEL_PREFIX_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


class GitHubIssuePreviewCreate(SQLModel):
    """Request payload for preparing GitHub issue markdown."""

    finding_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)
    limit: int = Field(default=20, ge=1, le=100)
    priority: FindingPriority | None = None
    label_prefix: str = Field(default="vuln-prioritizer", min_length=1, max_length=80)
    milestone: int | None = Field(default=None, ge=1)
    include_evidence_refs: bool = True

    @field_validator("label_prefix")
    @classmethod
    def validate_label_prefix(cls, value: str) -> str:
        stripped = value.strip()
        if not GITHUB_LABEL_PREFIX_RE.fullmatch(stripped):
            raise ValueError("label_prefix may contain only letters, numbers, '.', '_', ':', '-'.")
        return stripped

    @field_validator("finding_ids")
    @classmethod
    def dedupe_finding_ids(cls, value: list[uuid.UUID]) -> list[uuid.UUID]:
        seen: set[uuid.UUID] = set()
        deduped: list[uuid.UUID] = []
        for finding_id in value:
            if finding_id not in seen:
                deduped.append(finding_id)
                seen.add(finding_id)
        return deduped


class GitHubIssueExportCreate(GitHubIssuePreviewCreate):
    """Request payload for dry-run or explicit GitHub issue creation."""

    repository: str = Field(min_length=3, max_length=200)
    token_env: str | None = Field(default=None, min_length=1, max_length=100)
    dry_run: bool = True

    @field_validator("repository")
    @classmethod
    def validate_repository(cls, value: str) -> str:
        stripped = value.strip()
        if not GITHUB_REPOSITORY_RE.fullmatch(stripped):
            raise ValueError("repository must use owner/name format.")
        return stripped

    @field_validator("token_env")
    @classmethod
    def validate_token_env(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not ENV_NAME_RE.fullmatch(stripped):
            raise ValueError("token_env must be an environment variable name.")
        return stripped


class GitHubIssuePreviewRecord(SQLModel):
    """Prepared GitHub issue markdown for one Workbench finding."""

    finding_id: uuid.UUID
    cve_id: str
    title: str
    body: str
    labels: list[str] = Field(default_factory=list)
    milestone: int | None = None
    duplicate_key: str
    evidence_refs: list[str] = Field(default_factory=list)


class GitHubIssuePreviewPublic(SQLModel):
    """Collection response for GitHub issue previews."""

    dry_run: bool = True
    count: int
    data: list[GitHubIssuePreviewRecord] = Field(default_factory=list)


class GitHubIssueExportRecord(GitHubIssuePreviewRecord):
    """GitHub issue export result for one prepared issue."""

    status: Literal["preview", "created", "skipped_duplicate"]
    issue_url: str | None = None
    issue_number: int | None = None


class GitHubIssueExportPublic(SQLModel):
    """Collection response for GitHub issue export attempts."""

    dry_run: bool
    created_count: int = 0
    skipped_count: int = 0
    count: int
    data: list[GitHubIssueExportRecord] = Field(default_factory=list)


class GitHubIssueExport(SQLModel, table=True):
    """Persisted idempotency record for externally created GitHub issues."""

    __tablename__ = "github_issue_export"
    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "repository",
            "duplicate_key",
            name="uq_github_issue_export_project_repository_duplicate",
        ),
        Index("ix_github_issue_export_project", "project_id"),
        Index("ix_github_issue_export_finding", "finding_id"),
        Index("ix_github_issue_export_created_at", "created_at"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    project_id: uuid.UUID = Field(foreign_key="project.id", nullable=False, ondelete="CASCADE")
    finding_id: uuid.UUID | None = Field(default=None, foreign_key="finding.id")
    repository: str = Field(max_length=200, sa_column=Column(String(200), nullable=False))
    duplicate_key: str = Field(max_length=512, sa_column=Column(String(512), nullable=False))
    title: str = Field(max_length=500, sa_column=Column(String(500), nullable=False))
    issue_url: str | None = Field(default=None, max_length=1000)
    issue_number: int | None = Field(default=None, sa_column=Column(Integer, nullable=True))
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
