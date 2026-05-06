"""Lightweight per-process rate limiting for the Workbench API."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from time import monotonic

from fastapi import Request

from app.core.config import Settings


@dataclass
class RateLimitDecision:
    """Result of a rate-limit check."""

    allowed: bool
    retry_after_seconds: int = 0


@dataclass
class InMemoryRateLimiter:
    """Sliding-window limiter intended for local and single-process deployments."""

    window_seconds: int = 60
    attempts: dict[str, deque[float]] = field(default_factory=lambda: defaultdict(deque))

    def check(self, key: str, *, limit: int) -> RateLimitDecision:
        """Return whether a request is allowed for the given key and limit."""
        if limit <= 0:
            return RateLimitDecision(allowed=True)
        now = monotonic()
        bucket = self.attempts[key]
        while bucket and now - bucket[0] >= self.window_seconds:
            bucket.popleft()
        if len(bucket) >= limit:
            retry_after = max(1, int(self.window_seconds - (now - bucket[0])))
            return RateLimitDecision(allowed=False, retry_after_seconds=retry_after)
        bucket.append(now)
        return RateLimitDecision(allowed=True)


def rate_limit_key(request: Request, settings: Settings) -> tuple[str, int] | None:
    """Return the rate-limit key and limit for a request."""
    if not settings.RATE_LIMIT_ENABLED:
        return None
    client_host = request.client.host if request.client else "unknown"
    path = request.url.path
    if path.endswith("/login/access-token"):
        username = _form_username_hint(request)
        return f"login:{client_host}:{username}", settings.LOGIN_RATE_LIMIT_PER_MINUTE
    if path.startswith(f"{settings.API_V1_STR}/"):
        return f"api:{client_host}", settings.API_RATE_LIMIT_PER_MINUTE
    return None


def _form_username_hint(request: Request) -> str:
    content_type = request.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" not in content_type:
        return "unknown"
    return "submitted"
