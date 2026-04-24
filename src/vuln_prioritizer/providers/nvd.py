"""NVD provider for CVE metadata and CVSS details."""

from __future__ import annotations

import os
import random
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from threading import Lock
from typing import Final

import requests

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.config import (
    DEFAULT_NVD_API_KEY_ENV,
    HTTP_MAX_RETRIES,
    HTTP_TIMEOUT_SECONDS,
    NVD_API_URL,
)
from vuln_prioritizer.models import NvdData
from vuln_prioritizer.utils import safe_float

DEFAULT_NVD_MAX_CONCURRENCY: Final = 4


@dataclass(slots=True, frozen=True)
class NvdFetchDiagnostics:
    requested: int = 0
    cache_hits: int = 0
    network_fetches: int = 0
    failures: int = 0
    content_hits: int = 0
    empty_records: int = 0
    stale_cache_hits: int = 0
    degraded: bool = False


class NvdProvider:
    """Client for the NVD CVE API 2.0."""

    def __init__(
        self,
        session: requests.Session | None = None,
        api_key: str | None = None,
        timeout_seconds: int = HTTP_TIMEOUT_SECONDS,
        max_retries: int = HTTP_MAX_RETRIES,
        max_concurrency: int = DEFAULT_NVD_MAX_CONCURRENCY,
        cache: FileCache | None = None,
        session_factory: type[requests.Session] | None = None,
    ) -> None:
        self.session = session
        self.session_factory = session_factory or requests.Session
        self._shared_session_lock = Lock()
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.max_concurrency = max(1, max_concurrency)
        self.cache = cache
        self.last_diagnostics = NvdFetchDiagnostics()

    @classmethod
    def from_env(
        cls,
        api_key_env: str = DEFAULT_NVD_API_KEY_ENV,
        session: requests.Session | None = None,
        cache: FileCache | None = None,
    ) -> NvdProvider:
        api_key = os.getenv(api_key_env)
        return cls(
            session=session,
            api_key=api_key,
            cache=cache,
            max_concurrency=DEFAULT_NVD_MAX_CONCURRENCY if api_key else 1,
        )

    def fetch_many(
        self,
        cve_ids: list[str],
        *,
        refresh: bool = False,
    ) -> tuple[dict[str, NvdData], list[str]]:
        """Fetch NVD data for each CVE with one request per identifier."""
        resolved: dict[str, NvdData] = {}
        warnings_by_cve: dict[str, list[str]] = {}
        pending_ids: list[str] = []
        seen_ids: set[str] = set()
        cache_hits = 0
        failures = 0
        stale_cache_hits = 0

        for cve_id in cve_ids:
            if cve_id in seen_ids:
                continue
            seen_ids.add(cve_id)
            try:
                cached = None if refresh else self._load_from_cache(cve_id)
                if cached is not None:
                    resolved[cve_id] = cached
                    cache_hits += 1
                    continue
            except Exception as exc:  # noqa: BLE001 - provider should degrade gracefully
                warnings_by_cve.setdefault(cve_id, []).append(
                    f"NVD cache load failed for {cve_id}: {exc}"
                )
            pending_ids.append(cve_id)

        if pending_ids:
            max_workers = min(self.max_concurrency, len(pending_ids))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures: dict[str, Future[NvdData]] = {
                    cve_id: executor.submit(self._fetch_and_cache_cve, cve_id)
                    for cve_id in pending_ids
                }
                for cve_id in pending_ids:
                    try:
                        resolved[cve_id] = futures[cve_id].result()
                    except Exception as exc:  # noqa: BLE001 - provider should degrade gracefully
                        try:
                            stale = self._load_from_cache(cve_id, allow_expired=True)
                        except Exception:  # noqa: BLE001 - invalid stale cache is not recoverable
                            stale = None
                        if stale is not None:
                            warnings_by_cve.setdefault(cve_id, []).append(
                                f"NVD lookup failed for {cve_id}; using expired cached data: {exc}"
                            )
                            resolved[cve_id] = stale
                            stale_cache_hits += 1
                        else:
                            warnings_by_cve.setdefault(cve_id, []).append(
                                f"NVD lookup failed for {cve_id}: {exc}"
                            )
                            resolved[cve_id] = NvdData(cve_id=cve_id)
                        failures += 1

        results: dict[str, NvdData] = {}
        warnings: list[str] = []
        for cve_id in cve_ids:
            if cve_id in results:
                continue
            results[cve_id] = resolved.get(cve_id, NvdData(cve_id=cve_id))
            warnings.extend(warnings_by_cve.get(cve_id, []))

        content_hits = sum(1 for item in results.values() if has_nvd_content(item))
        self.last_diagnostics = NvdFetchDiagnostics(
            requested=len(cve_ids),
            cache_hits=cache_hits,
            network_fetches=len(pending_ids),
            failures=failures,
            content_hits=content_hits,
            empty_records=max(len(results) - content_hits, 0),
            stale_cache_hits=stale_cache_hits,
            degraded=failures > 0 or stale_cache_hits > 0,
        )

        return results, warnings

    def _load_from_cache(self, cve_id: str, *, allow_expired: bool = False) -> NvdData | None:
        if self.cache is None:
            return None
        cached_payload = self.cache.get_json("nvd", cve_id, allow_expired=allow_expired)
        if cached_payload is None:
            return None
        return NvdData.model_validate(cached_payload)

    def _store_in_cache(self, data: NvdData) -> None:
        if self.cache is None:
            return
        self.cache.set_json("nvd", data.cve_id, data.model_dump())

    def _fetch_and_cache_cve(self, cve_id: str) -> NvdData:
        payload = self._request_cve(cve_id)
        data = self.parse_payload(cve_id, payload)
        self._store_in_cache(data)
        return data

    def _request_cve(self, cve_id: str) -> dict:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        params = {"cveId": cve_id}

        attempt = 0
        last_error: Exception | None = None
        while attempt < self.max_retries:
            attempt += 1
            try:
                response = self._session_get(params=params, headers=headers)
                if response.status_code == 404:
                    return {}
                if response.status_code in {429, 500, 502, 503, 504} and attempt < self.max_retries:
                    time.sleep(_retry_delay(response, attempt))
                    continue
                response.raise_for_status()
                return response.json()
            except requests.RequestException as exc:
                last_error = exc
                status_code = getattr(getattr(exc, "response", None), "status_code", None)
                if status_code in {429, 500, 502, 503, 504} and attempt < self.max_retries:
                    time.sleep(_retry_delay(getattr(exc, "response", None), attempt))
                    continue
                break

        if last_error is not None:
            raise RuntimeError(str(last_error)) from last_error
        raise RuntimeError("NVD request failed without a response")

    def _session_get(self, *, params: dict[str, str], headers: dict[str, str]) -> requests.Response:
        if self.session is not None:
            with self._shared_session_lock:
                return self.session.get(
                    NVD_API_URL,
                    params=params,
                    headers=headers,
                    timeout=self.timeout_seconds,
                )

        session = self.session_factory()
        try:
            return session.get(
                NVD_API_URL,
                params=params,
                headers=headers,
                timeout=self.timeout_seconds,
            )
        finally:
            session.close()

    @staticmethod
    def parse_payload(cve_id: str, payload: dict) -> NvdData:
        """Parse a single NVD response payload."""
        vulnerabilities = payload.get("vulnerabilities") or []
        if not vulnerabilities:
            return NvdData(cve_id=cve_id)

        cve = (vulnerabilities[0] or {}).get("cve") or {}
        score, severity, version, vector = _extract_cvss(cve.get("metrics") or {})

        cwes: list[str] = []
        for weakness in cve.get("weaknesses") or []:
            for description in weakness.get("description") or []:
                value = description.get("value")
                if value and value not in cwes:
                    cwes.append(value)

        references = []
        reference_tags: dict[str, list[str]] = {}
        for reference in cve.get("references") or []:
            url = reference.get("url")
            if not url:
                continue
            references.append(url)
            tags = [str(tag).strip() for tag in reference.get("tags") or [] if str(tag).strip()]
            if tags:
                reference_tags[url] = tags

        return NvdData(
            cve_id=cve_id,
            description=_pick_description(cve.get("descriptions") or []),
            cvss_base_score=score,
            cvss_severity=severity,
            cvss_version=version,
            cvss_vector=vector,
            vulnerability_status=cve.get("vulnStatus"),
            published=cve.get("published"),
            last_modified=cve.get("lastModified"),
            cwes=cwes,
            references=references,
            reference_tags=reference_tags,
        )


def _pick_description(descriptions: list[dict]) -> str | None:
    for description in descriptions:
        if description.get("lang") == "en" and description.get("value"):
            return description["value"]
    for description in descriptions:
        if description.get("value"):
            return description["value"]
    return None


def _extract_cvss(metrics: dict) -> tuple[float | None, str | None, str | None, str | None]:
    versions = {
        "cvssMetricV40": "4.0",
        "cvssMetricV31": "3.1",
        "cvssMetricV30": "3.0",
        "cvssMetricV2": "2.0",
    }
    for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_key) or []
        if not entries:
            continue
        metric = entries[0] or {}
        cvss_data = metric.get("cvssData") or {}
        score = safe_float(cvss_data.get("baseScore"))
        severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity")
        vector = cvss_data.get("vectorString")
        if score is not None or severity:
            return score, severity, versions[metric_key], vector
    return None, None, None, None


def _retry_delay(response: requests.Response | None, attempt: int) -> float:
    headers = {} if response is None else getattr(response, "headers", {}) or {}
    retry_after = headers.get("Retry-After")
    if retry_after:
        try:
            return max(float(retry_after), 0.0)
        except ValueError:
            pass
    return float(attempt) + random.uniform(0.0, 0.25)


def has_nvd_content(item: NvdData) -> bool:
    return any(
        [
            item.description is not None,
            item.cvss_base_score is not None,
            item.cvss_severity is not None,
            item.cvss_version is not None,
            item.cvss_vector is not None,
            item.vulnerability_status is not None,
            item.published is not None,
            item.last_modified is not None,
            bool(item.cwes),
            bool(item.references),
            bool(item.reference_tags),
        ]
    )
