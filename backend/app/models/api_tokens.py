"""Scoped service-token models for the template Workbench API."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import field_validator
from sqlalchemy import JSON, Column, DateTime, Index, String
from sqlmodel import Field, SQLModel

from app.models.base import get_datetime_utc

ApiTokenScope = Literal["read", "import", "report", "admin"]
API_TOKEN_SCOPES: tuple[ApiTokenScope, ...] = ("read", "import", "report", "admin")


def normalize_api_token_scopes(scopes: list[str] | tuple[str, ...]) -> list[ApiTokenScope]:
    """Return deduplicated API token scopes in canonical order."""
    requested = {scope.strip().lower() for scope in scopes if scope.strip()}
    invalid = sorted(requested - set(API_TOKEN_SCOPES))
    if invalid:
        joined = ", ".join(invalid)
        raise ValueError(f"Unsupported API token scope: {joined}")
    if not requested:
        raise ValueError("At least one API token scope is required.")
    return [scope for scope in API_TOKEN_SCOPES if scope in requested]


class ApiTokenCreate(SQLModel):
    """Request payload for creating a scoped service token."""

    name: str = Field(min_length=1, max_length=200)
    scopes: list[ApiTokenScope] = Field(default_factory=lambda: ["read"])

    @field_validator("name")
    @classmethod
    def strip_name(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Token name is required.")
        return stripped

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, value: list[str]) -> list[ApiTokenScope]:
        return normalize_api_token_scopes(value)


class ApiTokenBase(SQLModel):
    """Shared persisted token metadata."""

    name: str = Field(min_length=1, max_length=200)
    token_hash: str = Field(sa_column=Column(String(128), nullable=False, unique=True))
    scopes_json: list[str] = Field(
        default_factory=lambda: ["read"],
        sa_column=Column(JSON, nullable=False),
    )


class ApiToken(ApiTokenBase, table=True):
    """Hashed scoped API token for CI/CD and local automation."""

    __tablename__ = "api_token"
    __table_args__ = (
        Index("ix_api_token_active", "revoked_at"),
        Index("ix_api_token_created_at", "created_at"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    last_used_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    revoked_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )

    @property
    def scopes(self) -> list[ApiTokenScope]:
        return normalize_api_token_scopes(list(self.scopes_json or []))


class ApiTokenPublic(SQLModel):
    """API token metadata returned after creation, listing, and revocation."""

    id: uuid.UUID
    name: str
    scopes: list[ApiTokenScope]
    active: bool
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


class ApiTokenCreatePublic(ApiTokenPublic):
    """Creation response that shows the cleartext token exactly once."""

    token: str


class ApiTokensPublic(SQLModel):
    """Collection response for token metadata."""

    data: list[ApiTokenPublic]
    count: int


def api_token_public(token: ApiToken) -> ApiTokenPublic:
    """Return public token metadata without the cleartext token or hash."""
    return ApiTokenPublic(
        id=token.id,
        name=token.name,
        scopes=token.scopes,
        active=token.revoked_at is None,
        created_at=token.created_at,
        last_used_at=token.last_used_at,
        revoked_at=token.revoked_at,
    )


def api_token_create_public(token: ApiToken, *, cleartext_token: str) -> ApiTokenCreatePublic:
    """Return the one-time token creation payload."""
    payload = api_token_public(token).model_dump()
    payload["token"] = cleartext_token
    return ApiTokenCreatePublic(**payload)


def scopes_payload(scopes: list[ApiTokenScope]) -> list[str]:
    """Return a JSON-serializable canonical scope payload."""
    return list(normalize_api_token_scopes(list(scopes)))


def scope_set(token: ApiToken | None) -> set[str]:
    """Return normalized scopes for authorization checks."""
    if token is None:
        return set()
    try:
        return set(token.scopes)
    except ValueError:
        return set()
