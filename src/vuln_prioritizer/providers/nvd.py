"""NVD provider for CVE metadata and CVSS details."""

from __future__ import annotations

import os
import time

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


class NvdProvider:
    """Client for the NVD CVE API 2.0."""

    def __init__(
        self,
        session: requests.Session | None = None,
        api_key: str | None = None,
        timeout_seconds: int = HTTP_TIMEOUT_SECONDS,
        max_retries: int = HTTP_MAX_RETRIES,
        cache: FileCache | None = None,
    ) -> None:
        self.session = session or requests.Session()
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.cache = cache

    @classmethod
    def from_env(
        cls,
        api_key_env: str = DEFAULT_NVD_API_KEY_ENV,
        session: requests.Session | None = None,
        cache: FileCache | None = None,
    ) -> NvdProvider:
        return cls(session=session, api_key=os.getenv(api_key_env), cache=cache)

    def fetch_many(
        self,
        cve_ids: list[str],
        *,
        refresh: bool = False,
    ) -> tuple[dict[str, NvdData], list[str]]:
        """Fetch NVD data for each CVE with one request per identifier."""
        results: dict[str, NvdData] = {}
        warnings: list[str] = []

        for cve_id in cve_ids:
            try:
                cached = None if refresh else self._load_from_cache(cve_id)
                if cached is not None:
                    results[cve_id] = cached
                    continue
                payload = self._request_cve(cve_id)
                results[cve_id] = self.parse_payload(cve_id, payload)
                self._store_in_cache(results[cve_id])
            except Exception as exc:  # noqa: BLE001 - provider should degrade gracefully
                warnings.append(f"NVD lookup failed for {cve_id}: {exc}")
                results[cve_id] = NvdData(cve_id=cve_id)

        return results, warnings

    def _load_from_cache(self, cve_id: str) -> NvdData | None:
        if self.cache is None:
            return None
        cached_payload = self.cache.get_json("nvd", cve_id)
        if cached_payload is None:
            return None
        return NvdData.model_validate(cached_payload)

    def _store_in_cache(self, data: NvdData) -> None:
        if self.cache is None:
            return
        self.cache.set_json("nvd", data.cve_id, data.model_dump())

    def _request_cve(self, cve_id: str) -> dict:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        params = {"cveId": cve_id}

        attempt = 0
        last_error: Exception | None = None
        while attempt < self.max_retries:
            attempt += 1
            try:
                response = self.session.get(
                    NVD_API_URL,
                    params=params,
                    headers=headers,
                    timeout=self.timeout_seconds,
                )
                if response.status_code == 404:
                    return {}
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
        raise RuntimeError("NVD request failed without a response")

    @staticmethod
    def parse_payload(cve_id: str, payload: dict) -> NvdData:
        """Parse a single NVD response payload."""
        vulnerabilities = payload.get("vulnerabilities") or []
        if not vulnerabilities:
            return NvdData(cve_id=cve_id)

        cve = (vulnerabilities[0] or {}).get("cve") or {}
        score, severity, version = _extract_cvss(cve.get("metrics") or {})

        cwes: list[str] = []
        for weakness in cve.get("weaknesses") or []:
            for description in weakness.get("description") or []:
                value = description.get("value")
                if value and value not in cwes:
                    cwes.append(value)

        references = [
            reference.get("url")
            for reference in cve.get("references") or []
            if reference.get("url")
        ]

        return NvdData(
            cve_id=cve_id,
            description=_pick_description(cve.get("descriptions") or []),
            cvss_base_score=score,
            cvss_severity=severity,
            cvss_version=version,
            published=cve.get("published"),
            last_modified=cve.get("lastModified"),
            cwes=cwes,
            references=references,
        )


def _pick_description(descriptions: list[dict]) -> str | None:
    for description in descriptions:
        if description.get("lang") == "en" and description.get("value"):
            return description["value"]
    for description in descriptions:
        if description.get("value"):
            return description["value"]
    return None


def _extract_cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
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
        if score is not None or severity:
            return score, severity, versions[metric_key]
    return None, None, None
