"""Runtime support tables for shared Workbench operations."""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Column, DateTime, Index
from sqlmodel import Field, SQLModel

from app.models.base import get_datetime_utc


class RateLimitBucket(SQLModel, table=True):
    """Shared fixed-window rate-limit bucket for non-local deployments."""

    __tablename__ = "rate_limit_bucket"
    __table_args__ = (Index("ix_rate_limit_bucket_window_started_at", "window_started_at"),)

    bucket_key: str = Field(max_length=255, primary_key=True)
    request_count: int = Field(nullable=False)
    window_started_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class RuntimeServiceHeartbeat(SQLModel, table=True):
    """Latest liveness signal for long-running local Workbench services."""

    __tablename__ = "runtime_service_heartbeat"
    __table_args__ = (
        Index(
            "ix_runtime_service_heartbeat_service_last_seen",
            "service_name",
            "last_seen_at",
        ),
    )

    service_name: str = Field(max_length=120, primary_key=True)
    instance_id: str = Field(max_length=160, primary_key=True)
    started_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    last_seen_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
