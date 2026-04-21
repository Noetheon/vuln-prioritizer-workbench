"""Small filesystem cache for provider responses."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from vuln_prioritizer.utils import iso_utc_now


class FileCache:
    """JSON file cache with TTL semantics."""

    def __init__(self, cache_dir: Path, ttl_hours: int) -> None:
        self.cache_dir = cache_dir
        self.ttl = timedelta(hours=ttl_hours)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get_json(self, namespace: str, key: str) -> Any | None:
        """Return cached JSON payload if present and not expired."""
        path = self._path_for(namespace, key)
        if not path.exists():
            return None

        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            cached_at_raw = document.get("cached_at")
            if not cached_at_raw:
                return None
            cached_at = datetime.fromisoformat(cached_at_raw)
            if cached_at.tzinfo is None:
                cached_at = cached_at.replace(tzinfo=UTC)
            if datetime.now(UTC) - cached_at > self.ttl:
                return None
            return document.get("payload")
        except (OSError, json.JSONDecodeError, ValueError):
            return None

    def set_json(self, namespace: str, key: str, payload: Any) -> None:
        """Persist a JSON-serializable payload."""
        path = self._path_for(namespace, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        document = {"key": key, "cached_at": iso_utc_now(), "payload": payload}
        path.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")

    def _path_for(self, namespace: str, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.cache_dir / namespace / f"{digest}.json"

    def latest_cached_at(self, namespace: str) -> str | None:
        """Return the newest cache timestamp recorded for a namespace."""
        return self.inspect_namespace(namespace)["latest_cached_at"]

    def inspect_namespace(self, namespace: str) -> dict[str, Any]:
        """Return cache metadata for a namespace."""
        namespace_path = self.cache_dir / namespace
        if not namespace_path.exists():
            return {
                "namespace": namespace,
                "file_count": 0,
                "valid_count": 0,
                "expired_count": 0,
                "invalid_count": 0,
                "latest_cached_at": None,
                "namespace_checksum": None,
            }

        newest: datetime | None = None
        valid_count = 0
        expired_count = 0
        invalid_count = 0
        file_count = 0
        checksum = hashlib.sha256()
        for path in namespace_path.glob("*.json"):
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, json.JSONDecodeError, ValueError):
                file_count += 1
                invalid_count += 1
                continue
            file_count += 1
            checksum.update(path.name.encode("utf-8"))
            checksum.update(text.encode("utf-8"))
            try:
                document = json.loads(text)
            except json.JSONDecodeError:
                invalid_count += 1
                continue
            cached_at = self._parse_cached_at(document.get("cached_at"))
            if cached_at is None:
                invalid_count += 1
                continue
            if newest is None or cached_at > newest:
                newest = cached_at
            if datetime.now(UTC) - cached_at > self.ttl:
                expired_count += 1
            else:
                valid_count += 1

        return {
            "namespace": namespace,
            "file_count": file_count,
            "valid_count": valid_count,
            "expired_count": expired_count,
            "invalid_count": invalid_count,
            "latest_cached_at": newest.isoformat() if newest is not None else None,
            "namespace_checksum": checksum.hexdigest() if file_count else None,
        }

    def _parse_cached_at(self, cached_at_raw: Any) -> datetime | None:
        if not cached_at_raw:
            return None
        try:
            cached_at = datetime.fromisoformat(str(cached_at_raw))
        except ValueError:
            return None
        if cached_at.tzinfo is None:
            cached_at = cached_at.replace(tzinfo=UTC)
        return cached_at
