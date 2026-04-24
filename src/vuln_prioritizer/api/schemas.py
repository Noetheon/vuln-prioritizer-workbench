"""Pydantic DTOs for the Workbench JSON API."""

from __future__ import annotations

from typing import Literal

from vuln_prioritizer.models import StrictModel


class ProjectCreateRequest(StrictModel):
    name: str
    description: str | None = None


class ReportCreateRequest(StrictModel):
    format: Literal["json", "markdown", "html"] = "html"
