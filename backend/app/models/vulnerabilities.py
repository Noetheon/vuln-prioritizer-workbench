"""Vulnerability domain models."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Column, DateTime, Text
from sqlmodel import Field, Relationship, SQLModel

from app.models.base import get_datetime_utc

if TYPE_CHECKING:
    from app.models.findings import Finding


class VulnerabilityBase(SQLModel):
    """Shared vulnerability fields."""

    cve_id: str = Field(min_length=1, max_length=64)
    source_id: str | None = Field(default=None, max_length=120)
    title: str | None = Field(default=None, max_length=500)
    description: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    cvss_score: float | None = None
    cvss_vector: str | None = Field(default=None, max_length=300)
    severity: str | None = Field(default=None, max_length=40)
    cwe: str | None = Field(default=None, max_length=200)
    published_at: str | None = Field(default=None, max_length=64)
    modified_at: str | None = Field(default=None, max_length=64)
    provider_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )


class Vulnerability(VulnerabilityBase, table=True):
    """Known vulnerability normalized from provider context."""

    __tablename__ = "vulnerability"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    cve_id: str = Field(min_length=1, max_length=64, unique=True, index=True)
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    findings: list["Finding"] = Relationship(back_populates="vulnerability")
