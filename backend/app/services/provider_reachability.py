"""Whether the live NVD, EPSS, and KEV feeds answer from this Workbench."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime

import requests

from app.domain.engine.config import EPSS_API_URL, KEV_FEED_URL, KEV_MIRROR_URL, NVD_API_URL
from app.models import ProviderReachabilityPublic, ProviderSourceReachabilityPublic

PROBE_TIMEOUT_SECONDS = 4
CACHE_SECONDS = 300
KEV_MIRROR_DETAIL = "Through the cisagov/kev-data mirror"

# One small request per feed, in the order the providers try them: KEV falls
# back to its official mirror like the KEV provider does. The URLs are fixed;
# nothing a user sends reaches them.
_PROBES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("nvd", "NVD", (f"{NVD_API_URL}?resultsPerPage=1",)),
    ("epss", "EPSS", (f"{EPSS_API_URL}?limit=1",)),
    ("kev", "KEV", (KEV_FEED_URL, KEV_MIRROR_URL)),
)


class ProviderReachabilityProbe:
    """Probes the live feeds and remembers the answer for a few minutes."""

    def __init__(
        self,
        *,
        session_factory: Callable[[], requests.Session] = requests.Session,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Use `session_factory` for the requests and `clock` for the cache age."""
        self._session_factory = session_factory
        self._clock = clock
        self._lock = threading.Lock()
        self._cached: ProviderReachabilityPublic | None = None
        self._cached_at = 0.0

    def check(self) -> ProviderReachabilityPublic:
        """Return the cached answer, or probe every feed once more."""
        with self._lock:
            if self._cached is not None and self._clock() - self._cached_at < CACHE_SECONDS:
                return self._cached
            with self._session_factory() as session:
                sources = [
                    _probe_source(session, source=source, label=label, urls=urls)
                    for source, label, urls in _PROBES
                ]
            self._cached = ProviderReachabilityPublic(
                checked_at=datetime.now(UTC),
                sources=sources,
            )
            self._cached_at = self._clock()
            return self._cached


def _probe_source(
    session: requests.Session,
    *,
    source: str,
    label: str,
    urls: tuple[str, ...],
) -> ProviderSourceReachabilityPublic:
    """Reachable when any of the feed's URLs answers; else the first failure."""
    first_failure: str | None = None
    for index, url in enumerate(urls):
        failure = _request_failure(session, url)
        if failure is None:
            return ProviderSourceReachabilityPublic(
                source=source,
                label=label,
                reachable=True,
                detail=KEV_MIRROR_DETAIL if index > 0 else None,
            )
        first_failure = first_failure or failure
    return ProviderSourceReachabilityPublic(
        source=source, label=label, reachable=False, detail=first_failure
    )


def _request_failure(session: requests.Session, url: str) -> str | None:
    """Why `url` did not answer, or None when it did."""
    try:
        # Streamed so the KEV catalog body is never downloaded.
        with session.get(url, stream=True, timeout=PROBE_TIMEOUT_SECONDS) as response:
            status = response.status_code
    except requests.Timeout:
        return "Timed out"
    except requests.exceptions.ProxyError:
        return "Proxy error"
    except requests.RequestException:
        return "Connection failed"
    return f"HTTP {status}" if status >= 400 else None


def app_reachability_probe(state: object) -> ProviderReachabilityProbe:
    """Return the probe kept on the app state, creating it on first use."""
    probe = getattr(state, "provider_reachability_probe", None)
    if not isinstance(probe, ProviderReachabilityProbe):
        probe = ProviderReachabilityProbe()
        state.provider_reachability_probe = probe  # type: ignore[attr-defined]
    return probe
