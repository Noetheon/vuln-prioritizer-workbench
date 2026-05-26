"""Provider update service exceptions."""

from __future__ import annotations


class ProviderUpdateConflict(RuntimeError):
    """Raised when a provider update is already active."""


class ProviderUpdateValidationError(ValueError):
    """Raised when a provider update request is invalid."""


class ProviderUpdateRefreshError(RuntimeError):
    """Raised when a live provider refresh degrades instead of producing a clean snapshot."""


__all__ = [
    "ProviderUpdateConflict",
    "ProviderUpdateValidationError",
    "ProviderUpdateRefreshError",
]
