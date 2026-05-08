from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vuln_prioritizer.cache import FileCache


def test_file_cache_round_trip(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache", ttl_hours=24)

    cache.set_json("nvd", "CVE-2026-0001", {"value": 1, "name": "demo"})

    assert cache.get_json("nvd", "CVE-2026-0001") == {"value": 1, "name": "demo"}


def test_file_cache_returns_none_for_expired_document(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache", ttl_hours=1)
    path = cache._path_for("epss", "CVE-2026-0002")
    path.parent.mkdir(parents=True, exist_ok=True)
    expired_at = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    path.write_text(
        json.dumps({"cached_at": expired_at, "payload": {"epss": 0.9}}),
        encoding="utf-8",
    )

    assert cache.get_json("epss", "CVE-2026-0002") is None


def test_file_cache_returns_none_for_invalid_json(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache", ttl_hours=24)
    path = cache._path_for("kev", "catalog")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{invalid", encoding="utf-8")

    assert cache.get_json("kev", "catalog") is None


def test_file_cache_inspect_namespace_reports_valid_expired_and_invalid_documents(
    tmp_path: Path,
) -> None:
    cache = FileCache(tmp_path / "cache", ttl_hours=1)
    cache.set_json("nvd", "CVE-2026-0001", {"value": 1})

    expired_path = cache._path_for("nvd", "CVE-2026-0002")
    expired_path.parent.mkdir(parents=True, exist_ok=True)
    expired_path.write_text(
        json.dumps(
            {
                "key": "CVE-2026-0002",
                "cached_at": (datetime.now(UTC) - timedelta(hours=2)).isoformat(),
                "payload": {"value": 2},
            }
        ),
        encoding="utf-8",
    )

    invalid_path = cache._path_for("nvd", "CVE-2026-0003")
    invalid_path.write_text("{invalid", encoding="utf-8")

    status = cache.inspect_namespace("nvd")

    assert status["file_count"] == 3
    assert status["valid_count"] == 1
    assert status["expired_count"] == 1
    assert status["invalid_count"] == 1
    assert status["latest_cached_at"] is not None
    assert status["namespace_checksum"] is not None


def test_file_cache_namespace_checksum_matches_sha256_of_cache_documents(
    tmp_path: Path,
) -> None:
    cache = FileCache(tmp_path / "cache", ttl_hours=24)
    path = cache._path_for("kev", "catalog")
    path.parent.mkdir(parents=True, exist_ok=True)
    document = json.dumps(
        {
            "key": "catalog",
            "cached_at": "2026-04-29T00:00:00+00:00",
            "payload": {"CVE-2026-1001": {"cve_id": "CVE-2026-1001", "in_kev": True}},
        },
        sort_keys=True,
    )
    path.write_text(document, encoding="utf-8")

    expected = hashlib.sha256()
    expected.update(path.name.encode("utf-8"))
    expected.update(document.encode("utf-8"))

    assert cache.inspect_namespace("kev")["namespace_checksum"] == expected.hexdigest()


def test_file_cache_reports_missing_namespace_and_normalizes_naive_timestamps(
    tmp_path: Path,
) -> None:
    cache = FileCache(tmp_path / "cache", ttl_hours=24)

    missing_status = cache.inspect_namespace("epss")
    assert missing_status == {
        "namespace": "epss",
        "file_count": 0,
        "valid_count": 0,
        "expired_count": 0,
        "invalid_count": 0,
        "latest_cached_at": None,
        "namespace_checksum": None,
    }

    path = cache._path_for("epss", "CVE-2026-0004")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "key": "CVE-2026-0004",
                "cached_at": datetime.now().replace(microsecond=0).isoformat(),
                "payload": {"epss": 0.42},
            }
        ),
        encoding="utf-8",
    )

    assert cache.get_json("epss", "CVE-2026-0004") == {"epss": 0.42}
    assert cache.latest_cached_at("epss") is not None
    assert cache.inspect_namespace("epss")["valid_count"] == 1


def test_file_cache_handles_missing_timestamps_and_expired_allowed_payloads(
    tmp_path: Path,
) -> None:
    cache = FileCache(tmp_path / "cache", ttl_hours=1)
    missing_timestamp = cache._path_for("nvd", "missing-ts")
    expired = cache._path_for("nvd", "expired-allowed")
    for path in (missing_timestamp, expired):
        path.parent.mkdir(parents=True, exist_ok=True)

    missing_timestamp.write_text(json.dumps({"payload": {"value": 1}}), encoding="utf-8")
    expired.write_text(
        json.dumps(
            {
                "key": "expired-allowed",
                "cached_at": (datetime.now(UTC) - timedelta(hours=3)).isoformat(),
                "payload": {"value": 2},
            }
        ),
        encoding="utf-8",
    )

    assert cache.get_json("nvd", "missing-ts") is None
    assert cache.get_json("nvd", "expired-allowed", allow_expired=True) == {"value": 2}

    invalid_timestamp = cache._path_for("nvd", "invalid-ts")
    invalid_timestamp.write_text(
        json.dumps({"cached_at": "not-a-date", "payload": {"value": 3}}),
        encoding="utf-8",
    )

    status = cache.inspect_namespace("nvd")
    assert status["expired_count"] == 1
    assert status["invalid_count"] == 2
