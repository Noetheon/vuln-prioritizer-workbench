"""Scoped service-token models for the Workbench API."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal, Self

from pydantic import field_validator, model_validator
from sqlalchemy import JSON, Column, DateTime, Index, String
from sqlmodel import Field, SQLModel

from app.models.base import get_datetime_utc

ApiTokenScope = Literal["read", "write", "import", "report", "admin"]
API_TOKEN_SCOPES: tuple[ApiTokenScope, ...] = (
    "read",
    "write",
    "import",
    "report",
    "admin",
)
DEFAULT_API_TOKEN_MODEL_EXPIRE_DAYS = 90


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
    project_id: uuid.UUID | None = None
    expires_at: datetime | None = None

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

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        normalized = _aware_utc(value)
        if normalized <= get_datetime_utc():
            raise ValueError("expires_at must be in the future.")
        return normalized

    @model_validator(mode="after")
    def validate_project_scope(self) -> Self:
        scope_names = set(self.scopes)
        if "admin" in scope_names:
            if self.project_id is not None:
                raise ValueError("Admin API tokens must not be project-scoped.")
            return self
        if self.project_id is None:
            raise ValueError("Non-admin API tokens require a project_id.")
        return self


class ApiTokenBase(SQLModel):
    """Shared persisted token metadata."""

    name: str = Field(min_length=1, max_length=200)
    token_hash: str = Field(sa_column=Column(String(128), nullable=False, unique=True))
    project_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="project.id",
        index=True,
        nullable=True,
        ondelete="CASCADE",
    )
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
        Index("ix_api_token_expires_at", "expires_at"),
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
    expires_at: datetime = Field(
        default_factory=lambda: (
            get_datetime_utc() + timedelta(days=DEFAULT_API_TOKEN_MODEL_EXPIRE_DAYS)
        ),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )

    @property
    def scopes(self) -> list[ApiTokenScope]:
        return normalize_api_token_scopes(list(self.scopes_json or []))


class ApiTokenPublic(SQLModel):
    """API token metadata returned after creation, listing, and revocation."""

    id: uuid.UUID
    name: str
    project_id: uuid.UUID | None
    scopes: list[ApiTokenScope]
    active: bool
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None
    expires_at: datetime


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
        project_id=token.project_id,
        scopes=token.scopes,
        active=is_api_token_active(token),
        created_at=token.created_at,
        last_used_at=token.last_used_at,
        revoked_at=token.revoked_at,
        expires_at=_aware_utc(token.expires_at),
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


def is_api_token_active(token: ApiToken, *, now: datetime | None = None) -> bool:
    """Return whether a token can currently authorize API requests."""
    current_time = now or get_datetime_utc()
    return token.revoked_at is None and _aware_utc(token.expires_at) > current_time


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


API_TOKEN_PROJECT_ID_ATTR = "_vpw_api_token_project_id"
API_TOKEN_SCOPES_ATTR = "_vpw_api_token_scopes"
API_TOKEN_ID_ATTR = "_vpw_api_token_id"


def attach_api_token_context(
    principal: object,
    *,
    token_id: uuid.UUID,
    project_id: uuid.UUID | None,
    scopes: set[str],
) -> None:
    """Attach service-token authorization context to a resolved user principal."""
    object.__setattr__(principal, API_TOKEN_ID_ATTR, token_id)
    object.__setattr__(principal, API_TOKEN_PROJECT_ID_ATTR, project_id)
    object.__setattr__(principal, API_TOKEN_SCOPES_ATTR, set(scopes))


def api_token_project_id(principal: object) -> uuid.UUID | None:
    """Return the service token's project scope when the principal came from a token."""
    value = getattr(principal, API_TOKEN_PROJECT_ID_ATTR, None)
    return value if isinstance(value, uuid.UUID) else None


def api_token_id(principal: object) -> uuid.UUID | None:
    """Return the service token ID when the principal came from a token."""
    value = getattr(principal, API_TOKEN_ID_ATTR, None)
    return value if isinstance(value, uuid.UUID) else None


def api_token_scopes(principal: object) -> set[str] | None:
    """Return service token scopes, or None when the principal came from a JWT."""
    value = getattr(principal, API_TOKEN_SCOPES_ATTR, None)
    if value is None:
        return None
    return {str(scope) for scope in value}
