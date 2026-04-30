"""API token scope helpers shared by legacy Workbench routes."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

ApiTokenScope = Literal["read", "import", "report", "admin"]
API_TOKEN_SCOPES: tuple[ApiTokenScope, ...] = ("read", "import", "report", "admin")


def normalize_api_token_scopes(
    scopes: Sequence[str] | None,
    *,
    default: list[ApiTokenScope] | None = None,
) -> list[ApiTokenScope]:
    """Return deduplicated API token scopes in canonical order."""
    requested_raw = scopes if scopes is not None else default
    requested = {scope.strip().lower() for scope in requested_raw or [] if scope.strip()}
    invalid = sorted(requested - set(API_TOKEN_SCOPES))
    if invalid:
        joined = ", ".join(invalid)
        raise ValueError(f"Unsupported API token scope: {joined}")
    if not requested:
        raise ValueError("At least one API token scope is required.")
    return [scope for scope in API_TOKEN_SCOPES if scope in requested]


def token_has_scope(scopes: list[str] | tuple[str, ...] | None, required_scope: str) -> bool:
    """Return whether token scopes satisfy a required scope."""
    try:
        normalized = set(normalize_api_token_scopes(scopes))
    except ValueError:
        return False
    return "admin" in normalized or required_scope in normalized
