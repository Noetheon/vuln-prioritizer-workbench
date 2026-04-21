"""CISA KEV provider with online and offline support."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import requests

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.config import HTTP_TIMEOUT_SECONDS, KEV_FEED_URL, KEV_MIRROR_URL
from vuln_prioritizer.models import KevData
from vuln_prioritizer.utils import normalize_cve_id


class KevProvider:
    """Client for the CISA KEV catalog."""

    def __init__(
        self,
        session: requests.Session | None = None,
        timeout_seconds: int = HTTP_TIMEOUT_SECONDS,
        feed_url: str = KEV_FEED_URL,
        mirror_url: str = KEV_MIRROR_URL,
        cache: FileCache | None = None,
    ) -> None:
        self.session = session or requests.Session()
        self.timeout_seconds = timeout_seconds
        self.feed_url = feed_url
        self.mirror_url = mirror_url
        self.cache = cache

    def fetch_many(
        self,
        cve_ids: list[str],
        offline_file: Path | None = None,
        *,
        refresh: bool = False,
    ) -> tuple[dict[str, KevData], list[str]]:
        """Load KEV data and return membership metadata for the requested CVEs."""
        warnings: list[str] = []

        try:
            index = self._load_index(offline_file, refresh=refresh)
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"KEV catalog load failed: {exc}")
            index = {}

        results: dict[str, KevData] = {}
        for cve_id in cve_ids:
            results[cve_id] = index.get(cve_id, KevData(cve_id=cve_id, in_kev=False))
        return results, warnings

    def _load_index(
        self, offline_file: Path | None, *, refresh: bool = False
    ) -> dict[str, KevData]:
        if offline_file is not None:
            index = self._load_offline_file(offline_file)
            if refresh:
                self._store_in_cache(index)
            return index

        cached_index = None if refresh else self._load_from_cache()
        if cached_index is not None:
            return cached_index

        try:
            payload = self._download_json(self.feed_url)
        except requests.RequestException:
            payload = self._download_json(self.mirror_url)

        index = self._index_vulnerabilities(payload.get("vulnerabilities") or [])
        self._store_in_cache(index)
        return index

    def _load_offline_file(self, path: Path) -> dict[str, KevData]:
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Offline KEV file not found: {path}")

        if path.suffix.lower() == ".json":
            payload = json.loads(path.read_text(encoding="utf-8"))
            vulnerabilities = payload.get("vulnerabilities") or []
            return self._index_vulnerabilities(vulnerabilities)

        if path.suffix.lower() == ".csv":
            with path.open("r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                return self._index_vulnerabilities(list(reader))

        raise ValueError("Offline KEV file must be .json or .csv")

    def _download_json(self, url: str) -> dict:
        response = self.session.get(url, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def _index_vulnerabilities(self, vulnerabilities: list[dict]) -> dict[str, KevData]:
        index: dict[str, KevData] = {}
        for vulnerability in vulnerabilities:
            cve_id = normalize_cve_id(
                vulnerability.get("cveID") or vulnerability.get("cveId") or vulnerability.get("cve")
            )
            if not cve_id:
                continue
            index[cve_id] = KevData(
                cve_id=cve_id,
                in_kev=True,
                vendor_project=vulnerability.get("vendorProject"),
                product=vulnerability.get("product"),
                date_added=vulnerability.get("dateAdded"),
                required_action=vulnerability.get("requiredAction"),
                due_date=vulnerability.get("dueDate"),
            )
        return index

    def _load_from_cache(self) -> dict[str, KevData] | None:
        if self.cache is None:
            return None
        cached_payload = self.cache.get_json("kev", "catalog")
        if cached_payload is None:
            return None
        return {cve_id: KevData.model_validate(item) for cve_id, item in cached_payload.items()}

    def _store_in_cache(self, index: dict[str, KevData]) -> None:
        if self.cache is None:
            return
        self.cache.set_json(
            "kev",
            "catalog",
            {cve_id: item.model_dump() for cve_id, item in index.items()},
        )
