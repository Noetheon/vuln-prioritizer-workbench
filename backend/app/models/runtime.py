"""Runtime support tables for shared Workbench operations."""

from datetime import datetime

from sqlalchemy import Column, DateTime, Index
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
