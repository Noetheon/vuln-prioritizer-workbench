"""Waiver configuration and health models."""

from __future__ import annotations

from pydantic import Field

from vuln_prioritizer.model_base import StrictModel


class WaiverRule(StrictModel):
    id: str | None = None
    cve_id: str
    owner: str
    reason: str
    expires_on: str
    review_on: str | None = None
    approval_ref: str | None = None
    ticket_url: str | None = None
    asset_ids: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)


class WaiverHealthSummary(StrictModel):
    total_rules: int = 0
    active_count: int = 0
    review_due_count: int = 0
    expired_count: int = 0
    review_window_days: int = 14
