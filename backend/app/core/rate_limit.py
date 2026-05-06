"""Lightweight per-process rate limiting for the Workbench API."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
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
    client_host = rate_limit_client_host(request, settings)
    path = request.url.path
    if path.endswith("/login/access-token"):
        username = _form_username_hint(request)
        return f"login:{client_host}:{username}", settings.LOGIN_RATE_LIMIT_PER_MINUTE
    if path.startswith(f"{settings.API_V1_STR}/"):
        return f"api:{client_host}", settings.API_RATE_LIMIT_PER_MINUTE
    return None


def rate_limit_client_host(request: Request, settings: Settings) -> str:
    """Return the client host used for rate-limit buckets."""
    direct_host = request.client.host if request.client else "unknown"
    if _is_trusted_proxy_host(direct_host, settings.TRUSTED_PROXY_CIDRS):
        forwarded_host = _forwarded_for_host(request.headers.get("x-forwarded-for"))
        if forwarded_host:
            return forwarded_host
    return direct_host


def _form_username_hint(request: Request) -> str:
    content_type = request.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" not in content_type:
        return "unknown"
    return "submitted"


def _is_trusted_proxy_host(host: str, trusted_proxy_cidrs: tuple[str, ...]) -> bool:
    if not trusted_proxy_cidrs:
        return False
    try:
        host_ip = ip_address(host)
    except ValueError:
        return False
    for cidr in trusted_proxy_cidrs:
        try:
            if host_ip in ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _forwarded_for_host(header_value: str | None) -> str | None:
    if not header_value:
        return None
    candidate = header_value.split(",", maxsplit=1)[0].strip().strip('"')
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]
    elif candidate.count(":") == 1 and "." in candidate.rsplit(":", maxsplit=1)[0]:
        candidate = candidate.rsplit(":", maxsplit=1)[0]
    try:
        return str(ip_address(candidate))
    except ValueError:
        return None
