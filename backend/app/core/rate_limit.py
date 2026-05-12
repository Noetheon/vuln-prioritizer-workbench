"""Rate limiting for the Workbench API."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network
from time import monotonic
from typing import Protocol, runtime_checkable

from fastapi import Request
from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.core.config import Settings


@dataclass
class RateLimitDecision:
    """Result of a rate-limit check."""

    allowed: bool
    retry_after_seconds: int = 0


@runtime_checkable
class RateLimiter(Protocol):
    """Common limiter interface used by HTTP middleware."""

    def check(self, key: str, *, limit: int, record: bool = True) -> RateLimitDecision:
        """Return whether a request is allowed for the given key and limit."""


@dataclass
class InMemoryRateLimiter:
    """Sliding-window limiter intended for local and single-process deployments."""

    window_seconds: int = 60
    attempts: dict[str, deque[float]] = field(default_factory=lambda: defaultdict(deque))
    max_keys: int = 10_000

    def check(self, key: str, *, limit: int, record: bool = True) -> RateLimitDecision:
        """Return whether a request is allowed for the given key and limit."""
        if limit <= 0:
            return RateLimitDecision(allowed=True)
        now = monotonic()
        self._prune_expired(now)
        if not record and key not in self.attempts:
            return RateLimitDecision(allowed=True)
        bucket = self.attempts[key]
        while bucket and now - bucket[0] >= self.window_seconds:
            bucket.popleft()
        if len(bucket) >= limit:
            retry_after = max(1, int(self.window_seconds - (now - bucket[0])))
            return RateLimitDecision(allowed=False, retry_after_seconds=retry_after)
        if record:
            bucket.append(now)
            self._enforce_key_bound()
        return RateLimitDecision(allowed=True)

    def _prune_expired(self, now: float) -> None:
        stale_keys = [
            key
            for key, bucket in self.attempts.items()
            if not bucket or now - bucket[-1] >= self.window_seconds
        ]
        for key in stale_keys:
            self.attempts.pop(key, None)

    def _enforce_key_bound(self) -> None:
        while len(self.attempts) > self.max_keys:
            oldest_key = min(
                self.attempts,
                key=lambda candidate: (
                    self.attempts[candidate][0] if self.attempts[candidate] else 0.0
                ),
            )
            self.attempts.pop(oldest_key, None)


@dataclass(frozen=True)
class DatabaseRateLimiter:
    """Database-backed fixed-window limiter for shared non-local deployments."""

    engine: Engine
    window_seconds: int = 60

    def check(self, key: str, *, limit: int, record: bool = True) -> RateLimitDecision:
        """Return whether a request is allowed using a shared database bucket."""
        if limit <= 0:
            return RateLimitDecision(allowed=True)

        now = datetime.now(UTC)
        cutoff = now - timedelta(seconds=self.window_seconds)
        with self.engine.begin() as connection:
            connection.execute(
                text("DELETE FROM rate_limit_bucket WHERE window_started_at <= :cutoff"),
                {"cutoff": cutoff},
            )
            if not record:
                row = (
                    connection.execute(
                        text(
                            "SELECT request_count, window_started_at "
                            "FROM rate_limit_bucket WHERE bucket_key = :bucket_key"
                        ),
                        {"bucket_key": key},
                    )
                    .mappings()
                    .first()
                )
                if row is None:
                    return RateLimitDecision(allowed=True)
                request_count = int(row["request_count"])
                if request_count < limit:
                    return RateLimitDecision(allowed=True)
                return RateLimitDecision(
                    allowed=False,
                    retry_after_seconds=_retry_after_seconds(
                        _aware_utc(row["window_started_at"]),
                        now,
                        self.window_seconds,
                    ),
                )

            connection.execute(
                text(
                    "INSERT INTO rate_limit_bucket "
                    "(bucket_key, request_count, window_started_at, updated_at) "
                    "VALUES (:bucket_key, 0, :window_started_at, :updated_at) "
                    "ON CONFLICT(bucket_key) DO NOTHING"
                ),
                {
                    "bucket_key": key,
                    "window_started_at": now,
                    "updated_at": now,
                },
            )
            increment = connection.execute(
                text(
                    "UPDATE rate_limit_bucket "
                    "SET request_count = request_count + 1, updated_at = :updated_at "
                    "WHERE bucket_key = :bucket_key AND request_count < :limit"
                ),
                {"bucket_key": key, "limit": limit, "updated_at": now},
            )
            if increment.rowcount == 1:
                return RateLimitDecision(allowed=True)

            blocked_row = (
                connection.execute(
                    text(
                        "SELECT window_started_at FROM rate_limit_bucket "
                        "WHERE bucket_key = :bucket_key"
                    ),
                    {"bucket_key": key},
                )
                .mappings()
                .first()
            )
            if blocked_row is None:
                return RateLimitDecision(allowed=True)
            return RateLimitDecision(
                allowed=False,
                retry_after_seconds=_retry_after_seconds(
                    _aware_utc(blocked_row["window_started_at"]),
                    now,
                    self.window_seconds,
                ),
            )


def create_rate_limiter(settings: Settings, engine: Engine) -> RateLimiter:
    """Return the limiter implementation for the configured deployment mode."""
    if settings.ENVIRONMENT == "local":
        return InMemoryRateLimiter()
    return DatabaseRateLimiter(engine)


def _aware_utc(value: datetime | str) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _retry_after_seconds(
    window_started_at: datetime,
    now: datetime,
    window_seconds: int,
) -> int:
    return max(
        1,
        int((window_started_at + timedelta(seconds=window_seconds) - now).total_seconds()),
    )


def rate_limit_key(request: Request, settings: Settings) -> tuple[str, int] | None:
    """Return the rate-limit key and limit for a request."""
    if not settings.RATE_LIMIT_ENABLED:
        return None
    client_host = rate_limit_client_host(request, settings)
    path = request.url.path
    if path.startswith(f"{settings.API_V1_STR}/"):
        return f"api:{client_host}", settings.API_RATE_LIMIT_PER_MINUTE
    return None


def rate_limit_client_host(request: Request, settings: Settings) -> str:
    """Return the client host used for rate-limit buckets."""
    direct_host = request.client.host if request.client else "unknown"
    if _is_trusted_proxy_host(direct_host, settings.TRUSTED_PROXY_CIDRS):
        forwarded_host = _forwarded_for_host(
            request.headers.get("x-forwarded-for"),
            settings.TRUSTED_PROXY_CIDRS,
        )
        if forwarded_host:
            return forwarded_host
    return direct_host


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


def _forwarded_for_host(
    header_value: str | None,
    trusted_proxy_cidrs: tuple[str, ...] = (),
) -> str | None:
    if not header_value:
        return None
    forwarded_hosts = [
        parsed_host
        for raw_candidate in header_value.split(",")
        if (parsed_host := _parse_forwarded_for_host(raw_candidate)) is not None
    ]
    for forwarded_host in reversed(forwarded_hosts):
        if not _is_trusted_proxy_host(forwarded_host, trusted_proxy_cidrs):
            return forwarded_host
    return forwarded_hosts[-1] if forwarded_hosts else None


def _parse_forwarded_for_host(raw_candidate: str) -> str | None:
    candidate = raw_candidate.strip().strip('"')
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]
    elif candidate.count(":") == 1 and "." in candidate.rsplit(":", maxsplit=1)[0]:
        candidate = candidate.rsplit(":", maxsplit=1)[0]
    try:
        return str(ip_address(candidate))
    except ValueError:
        return None
