"""FIRST EPSS provider."""

from __future__ import annotations

import time

import requests

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.config import (
    EPSS_API_URL,
    EPSS_QUERY_CHAR_LIMIT,
    HTTP_MAX_RETRIES,
    HTTP_TIMEOUT_SECONDS,
)
from vuln_prioritizer.models import EpssData, ProviderLookupDiagnostics
from vuln_prioritizer.utils import chunk_cve_ids, safe_float


class EpssProvider:
    """Client for the FIRST EPSS API."""

    def __init__(
        self,
        session: requests.Session | None = None,
        timeout_seconds: int = HTTP_TIMEOUT_SECONDS,
        max_retries: int = HTTP_MAX_RETRIES,
        cache: FileCache | None = None,
    ) -> None:
        self.session = session or requests.Session()
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.cache = cache
        self.last_diagnostics = ProviderLookupDiagnostics()

    def fetch_many(
        self,
        cve_ids: list[str],
        *,
        refresh: bool = False,
    ) -> tuple[dict[str, EpssData], list[str]]:
        """Fetch EPSS records in chunks below the documented query limit."""
        results: dict[str, EpssData] = {}
        warnings: list[str] = []
        missing: list[str] = []
        cache_hits = 0
        failures = 0
        stale_cache_hits = 0

        for cve_id in cve_ids:
            cached = None if refresh else self._load_from_cache(cve_id)
            if cached is not None:
                results[cve_id] = cached
                cache_hits += 1
            else:
                missing.append(cve_id)

        for chunk in chunk_cve_ids(missing, EPSS_QUERY_CHAR_LIMIT):
            try:
                payload = self._request_chunk(chunk)
            except Exception as exc:  # noqa: BLE001
                failures += len(chunk)
                recovered: list[str] = []
                for cve_id in chunk:
                    try:
                        stale = self._load_from_cache(cve_id, allow_expired=True)
                    except Exception:  # noqa: BLE001 - invalid stale cache is not recoverable
                        stale = None
                    if stale is None:
                        continue
                    results[cve_id] = stale
                    stale_cache_hits += 1
                    recovered.append(cve_id)
                suffix = (
                    "; using expired cached data for " + ", ".join(recovered) if recovered else ""
                )
                warnings.append(
                    "EPSS lookup failed for chunk " + ",".join(chunk) + f": {exc}" + suffix
                )
                continue

            seen_in_chunk: set[str] = set()
            for item in payload.get("data") or []:
                cve_id = item.get("cve")
                if not cve_id:
                    continue
                seen_in_chunk.add(cve_id)
                results[cve_id] = EpssData(
                    cve_id=cve_id,
                    epss=safe_float(item.get("epss")),
                    percentile=safe_float(item.get("percentile")),
                    date=item.get("date") or item.get("created"),
                )
                self._store_in_cache(results[cve_id])

            for cve_id in chunk:
                if cve_id in seen_in_chunk:
                    continue
                empty_result = EpssData(cve_id=cve_id)
                results[cve_id] = empty_result
                self._store_in_cache(empty_result)

        for cve_id in cve_ids:
            results.setdefault(cve_id, EpssData(cve_id=cve_id))

        content_hits = sum(1 for item in results.values() if has_epss_content(item))
        self.last_diagnostics = ProviderLookupDiagnostics(
            requested=len(cve_ids),
            cache_hits=cache_hits,
            network_fetches=len(missing),
            failures=failures,
            content_hits=content_hits,
            empty_records=max(len(cve_ids) - content_hits, 0),
            stale_cache_hits=stale_cache_hits,
            degraded=failures > 0 or stale_cache_hits > 0,
        )
        return results, warnings

    def _load_from_cache(self, cve_id: str, *, allow_expired: bool = False) -> EpssData | None:
        if self.cache is None:
            return None
        cached_payload = self.cache.get_json("epss", cve_id, allow_expired=allow_expired)
        if cached_payload is None:
            return None
        return EpssData.model_validate(cached_payload)

    def _store_in_cache(self, data: EpssData) -> None:
        if self.cache is None:
            return
        self.cache.set_json("epss", data.cve_id, data.model_dump())

    def _request_chunk(self, cve_ids: list[str]) -> dict:
        params = {"cve": ",".join(cve_ids)}

        attempt = 0
        last_error: Exception | None = None
        while attempt < self.max_retries:
            attempt += 1
            try:
                response = self.session.get(
                    EPSS_API_URL,
                    params=params,
                    timeout=self.timeout_seconds,
                )
                if response.status_code in {429, 500, 502, 503, 504} and attempt < self.max_retries:
                    time.sleep(attempt)
                    continue
                response.raise_for_status()
                return response.json()
            except requests.RequestException as exc:
                last_error = exc
                status_code = getattr(getattr(exc, "response", None), "status_code", None)
                if status_code in {429, 500, 502, 503, 504} and attempt < self.max_retries:
                    time.sleep(attempt)
                    continue
                break

        if last_error is not None:
            raise RuntimeError(str(last_error)) from last_error
        raise RuntimeError("EPSS request failed without a response")


def has_epss_content(item: EpssData) -> bool:
    return item.epss is not None or item.percentile is not None or item.date is not None
