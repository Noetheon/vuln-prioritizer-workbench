"""Minimal template auth models for the first FastAPI-template login slice."""

from __future__ import annotations

from pydantic import BaseModel


class Token(BaseModel):
    """OAuth2 bearer token response."""

    access_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    """JWT payload accepted by the template shell."""

    sub: str | None = None


class UserPublic(BaseModel):
    """Public user shape exposed by the template shell auth smoke."""

    id: str
    email: str
    is_active: bool = True
    is_superuser: bool = True
    full_name: str | None = None


class MigrationStatus(BaseModel):
    """Template migration state for the Workbench adapter."""

    phase: str
    legacy_workbench_mounted: bool


class WorkbenchStatus(BaseModel):
    """Status response returned by the template Workbench adapter."""

    status: str
    app: str
    core_package: str
    core_version: str
    legacy_api_prefix: str
    migration: MigrationStatus
