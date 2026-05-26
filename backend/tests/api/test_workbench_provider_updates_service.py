from __future__ import annotations

import os
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.models import ProviderUpdateJobCreate
from app.services import provider_update_locking as provider_update_locking_module
from app.services import provider_update_snapshot as provider_update_snapshot_module
from app.services.provider_updates import (
    PROVIDER_UPDATE_LOCK_FILE,
    PROVIDER_UPDATE_LOCK_STALE_SECONDS,
    ProviderUpdateConflict,
    ProviderUpdateValidationError,
    _cached_provider_records,
    _latest_epss_date,
    _latest_kev_date,
    _latest_nvd_sync,
    _load_latest_snapshot_items,
    _normalize_sources,
    _other_running_update,
    _provider_records_for_snapshot,
    _provider_source_metadata,
    _provider_update_cve_ids,
    _provider_update_lock,
    _provider_update_lock_is_stale,
    _provider_update_project,
    _redacted_payload,
)
from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.models import (
    EpssData,
    KevData,
    NvdData,
    ProviderSnapshotItem,
    ProviderSnapshotMetadata,
    ProviderSnapshotReport,
)
from vuln_prioritizer.provider_snapshot import generate_provider_snapshot_json


def test_provider_update_source_normalization_deduplicates_valid_sources() -> None:
    assert _normalize_sources([" NVD ", "epss", "nvd", "KEV"]) == ["nvd", "epss", "kev"]


@pytest.mark.parametrize(
    ("sources", "expected_message"),
    [
        ([], "At least one provider source is required."),
        (["nvd", "vulndb"], "Invalid provider source\\(s\\): vulndb"),
    ],
)
def test_provider_update_source_normalization_rejects_invalid_requests(
    sources: list[str],
    expected_message: str,
) -> None:
    with pytest.raises(ProviderUpdateValidationError, match=expected_message):
        _normalize_sources(sources)


def test_provider_update_cve_selection_normalizes_deduplicates_and_limits() -> None:
    payload = ProviderUpdateJobCreate(
        cve_ids=[" cve-2024-0002 ", "CVE-2024-0002", "CVE-2024-0003"],
        max_cves=1,
    )

    assert _provider_update_cve_ids(object(), payload=payload) == ["CVE-2024-0002"]

    with pytest.raises(ProviderUpdateValidationError, match="Invalid CVE id"):
        _provider_update_cve_ids(object(), payload=ProviderUpdateJobCreate(cve_ids=["bad"]))


def test_provider_update_cve_selection_falls_back_to_findings_and_existing_project() -> None:
    class FakeExecResult:
        def __init__(self, values: list[Any]) -> None:
            self.values = values

        def all(self) -> list[Any]:
            return self.values

        def first(self) -> Any:
            return self.values[0] if self.values else None

    class FakeSession:
        added = False
        flushed = False

        def __init__(self, values: list[Any]) -> None:
            self.values = values

        def exec(self, _statement: object) -> FakeExecResult:
            return FakeExecResult(self.values)

        def add(self, _value: object) -> None:
            self.added = True

        def flush(self) -> None:
            self.flushed = True

    cve_session = FakeSession(["CVE-2024-0002", "CVE-2024-0002", "CVE-2024-0003"])
    assert _provider_update_cve_ids(
        cve_session,  # type: ignore[arg-type]
        payload=ProviderUpdateJobCreate(max_cves=2),
    ) == ["CVE-2024-0002", "CVE-2024-0003"]

    existing_project = SimpleNamespace(id="project-1")
    project_session = FakeSession([existing_project])
    assert (
        _provider_update_project(  # type: ignore[arg-type]
            project_session,
        )
        is existing_project
    )
    assert project_session.added is False
    assert project_session.flushed is False

    active_run = SimpleNamespace(id="00000000-0000-4000-8000-000000000123")
    repository = SimpleNamespace(get_running_provider_update_run=lambda: active_run)
    assert _other_running_update(repository, "different-run") is active_run  # type: ignore[arg-type]


def test_provider_update_lock_rejects_active_lock(tmp_path: Path) -> None:
    (tmp_path / PROVIDER_UPDATE_LOCK_FILE).write_text("active", encoding="utf-8")

    with pytest.raises(ProviderUpdateConflict, match="Provider update already running"):
        with _provider_update_lock(tmp_path):
            pass


def test_provider_update_lock_reclaims_stale_lock(tmp_path: Path) -> None:
    lock_path = tmp_path / PROVIDER_UPDATE_LOCK_FILE
    lock_path.write_text("stale", encoding="utf-8")
    stale_timestamp = time.time() - PROVIDER_UPDATE_LOCK_STALE_SECONDS - 1
    os.utime(lock_path, (stale_timestamp, stale_timestamp))

    with _provider_update_lock(tmp_path) as acquired_lock:
        assert acquired_lock == lock_path
        assert lock_path.exists()

    assert not lock_path.exists()


def test_provider_update_lock_stale_check_treats_stat_errors_as_active(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / PROVIDER_UPDATE_LOCK_FILE

    def fail_stat(_path: Path) -> object:
        raise OSError("gone")

    monkeypatch.setattr(Path, "stat", fail_stat)

    assert _provider_update_lock_is_stale(lock_path) is False


def test_provider_update_lock_rejects_stale_lock_reclaim_race(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / PROVIDER_UPDATE_LOCK_FILE
    lock_path.write_text("stale", encoding="utf-8")
    open_calls = 0

    def fail_open(*_args: object, **_kwargs: object) -> int:
        nonlocal open_calls
        open_calls += 1
        raise FileExistsError("race")

    monkeypatch.setattr(provider_update_locking_module.os, "open", fail_open)
    monkeypatch.setattr(
        provider_update_locking_module,
        "_provider_update_lock_is_stale",
        lambda _path: True,
    )

    with pytest.raises(ProviderUpdateConflict, match="Provider update already running"):
        with _provider_update_lock(tmp_path):
            pass

    assert open_calls == 2
    assert not lock_path.exists()


def test_cached_provider_records_load_valid_nvd_and_warn_on_invalid_payloads(
    tmp_path: Path,
) -> None:
    cache = FileCache(tmp_path / "cache", ttl_hours=24)
    cache.set_json(
        "nvd",
        "CVE-2024-3094",
        {"cve_id": "CVE-2024-3094", "published": "2024-03-29T00:00:00Z"},
    )
    cache.set_json("nvd", "CVE-2021-44228", {"description": "missing CVE id"})

    records, warnings = _cached_provider_records(
        source="nvd",
        cache=cache,
        cve_ids=["CVE-2024-3094", "CVE-2021-44228", "CVE-1999-0001"],
    )

    assert records["CVE-2024-3094"].published == "2024-03-29T00:00:00Z"
    assert "CVE-2021-44228" not in records
    assert warnings == ["Cache-only NVD data invalid for CVE(s): CVE-2021-44228."]


def test_cached_provider_records_load_kev_catalog_and_warn_on_invalid_items(
    tmp_path: Path,
) -> None:
    cache = FileCache(tmp_path / "cache", ttl_hours=24)
    cache.set_json(
        "kev",
        "catalog",
        {
            "CVE-2024-3094": {
                "cve_id": "CVE-2024-3094",
                "date_added": "2024-03-29",
                "in_kev": True,
            },
            "CVE-2021-44228": {"in_kev": True},
        },
    )

    records, warnings = _cached_provider_records(
        source="kev",
        cache=cache,
        cve_ids=["CVE-2024-3094", "CVE-2021-44228", "CVE-1999-0001"],
    )

    assert records["CVE-2024-3094"].in_kev is True
    assert "CVE-1999-0001" not in records
    assert warnings == ["Cache-only KEV data invalid for CVE(s): CVE-2021-44228."]


def test_cached_provider_records_warn_when_kev_catalog_is_missing(tmp_path: Path) -> None:
    records, warnings = _cached_provider_records(
        source="kev",
        cache=FileCache(tmp_path / "cache", ttl_hours=24),
        cve_ids=["CVE-2024-3094"],
    )

    assert records == {}
    assert warnings == ["Cache-only KEV catalog is missing from the local cache."]


def test_provider_records_merge_cache_only_fetches_with_previous_snapshot(
    tmp_path: Path,
) -> None:
    baseline_items = {
        "CVE-2024-3094": ProviderSnapshotItem(
            cve_id="CVE-2024-3094",
            epss=EpssData(cve_id="CVE-2024-3094", epss=0.72, date="2024-03-30"),
        )
    }

    records, warnings, counts = _provider_records_for_snapshot(
        source="epss",
        cache=FileCache(tmp_path / "cache", ttl_hours=24),
        cve_ids=["CVE-2024-3094", "CVE-1999-0001"],
        cache_only=True,
        baseline_items=baseline_items,
    )

    assert records["CVE-2024-3094"].epss == 0.72
    assert warnings == ["EPSS data missing for 1 CVE(s)."]
    assert counts == {
        "records": 1,
        "fetched": 0,
        "fallback_from_previous_snapshot": 1,
        "missing": 1,
    }


def test_provider_records_fetch_live_source_branches_without_network(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class FakeNvdProvider:
        @classmethod
        def from_env(cls, *, api_key_env: str, cache: FileCache) -> FakeNvdProvider:
            assert api_key_env == "CUSTOM_NVD_KEY"
            assert isinstance(cache, FileCache)
            return cls()

        def fetch_many(
            self,
            cve_ids: list[str],
            *,
            refresh: bool = False,
        ) -> tuple[dict[str, NvdData], list[str]]:
            assert refresh is True
            return ({cve_ids[0]: NvdData(cve_id=cve_ids[0], description="known")}, [])

    class FakeEpssProvider:
        def __init__(self, *, cache: FileCache) -> None:
            assert isinstance(cache, FileCache)

        def fetch_many(
            self,
            cve_ids: list[str],
            *,
            refresh: bool = False,
        ) -> tuple[dict[str, EpssData], list[str]]:
            assert refresh is True
            return ({cve_ids[0]: EpssData(cve_id=cve_ids[0], epss=0.7)}, [])

    class FakeKevProvider:
        def __init__(self, *, cache: FileCache) -> None:
            assert isinstance(cache, FileCache)

        def fetch_many(
            self,
            cve_ids: list[str],
            *,
            refresh: bool = False,
        ) -> tuple[dict[str, KevData], list[str]]:
            assert refresh is True
            return ({cve_ids[0]: KevData(cve_id=cve_ids[0], in_kev=True)}, [])

    monkeypatch.setattr(provider_update_snapshot_module, "NvdProvider", FakeNvdProvider)
    monkeypatch.setattr(provider_update_snapshot_module, "EpssProvider", FakeEpssProvider)
    monkeypatch.setattr(provider_update_snapshot_module, "KevProvider", FakeKevProvider)

    for source, expected_type in (
        ("nvd", NvdData),
        ("epss", EpssData),
        ("kev", KevData),
    ):
        records, warnings, counts = _provider_records_for_snapshot(
            source=source,
            cve_ids=["CVE-2024-3094"],
            cache=FileCache(tmp_path / source, ttl_hours=24),
            cache_only=False,
            baseline_items={},
            nvd_api_key_env="CUSTOM_NVD_KEY",
        )
        assert isinstance(records["CVE-2024-3094"], expected_type)
        assert warnings == []
        assert counts == {
            "records": 1,
            "fetched": 1,
            "fallback_from_previous_snapshot": 0,
            "missing": 0,
        }


def test_latest_provider_snapshot_reuse_reports_missing_invalid_and_valid_artifacts(
    tmp_path: Path,
) -> None:
    snapshot_root = tmp_path / "snapshots"
    snapshot_root.mkdir()
    outside_root = tmp_path / "outside.json"
    outside_root.write_text("{}", encoding="utf-8")
    settings = SimpleNamespace(provider_snapshot_dir_path=snapshot_root)

    no_path_snapshot = SimpleNamespace(source_metadata_json={})
    assert _load_latest_snapshot_items(no_path_snapshot, settings=settings) == (
        {},
        ["Latest provider snapshot has no reusable source artifact path."],
    )

    missing_snapshot = SimpleNamespace(source_metadata_json={"snapshot_file": "missing.json"})
    assert _load_latest_snapshot_items(missing_snapshot, settings=settings) == (
        {},
        ["Latest provider snapshot artifact is no longer available on disk."],
    )

    for unsafe_value in ("../outside.json", str(outside_root)):
        assert _load_latest_snapshot_items(
            SimpleNamespace(source_metadata_json={"snapshot_file": unsafe_value}),
            settings=settings,
        ) == (
            {},
            ["Latest provider snapshot artifact path is outside the snapshot directory."],
        )

    invalid_file = snapshot_root / "invalid.json"
    invalid_file.write_text("{}", encoding="utf-8")
    invalid_snapshot = SimpleNamespace(source_metadata_json={"snapshot_file": invalid_file.name})
    _items, warnings = _load_latest_snapshot_items(invalid_snapshot, settings=settings)
    assert warnings[0].startswith("Latest provider snapshot artifact could not be reused:")

    valid_file = snapshot_root / "valid.json"
    valid_file.write_text(
        generate_provider_snapshot_json(
            ProviderSnapshotReport(
                metadata=ProviderSnapshotMetadata(
                    snapshot_id="snapshot-1",
                    generated_at="2026-04-24T09:00:00Z",
                    input_paths=[],
                    input_format="unit",
                    selected_sources=["nvd"],
                    requested_cves=1,
                    output_path=valid_file.name,
                    cache_enabled=True,
                    cache_only=True,
                    cache_dir=None,
                    source_hashes={},
                    source_metadata={},
                    nvd_api_key_env=None,
                ),
                items=[ProviderSnapshotItem(cve_id="CVE-2024-3094")],
                warnings=[],
            )
        ),
        encoding="utf-8",
    )
    items, warnings = _load_latest_snapshot_items(
        SimpleNamespace(source_metadata_json={"snapshot_file": valid_file.name}),
        settings=settings,
    )
    assert sorted(items) == ["CVE-2024-3094"]
    assert warnings == []


def test_provider_update_metadata_summarizes_sources_and_latest_sync_values() -> None:
    metadata = _provider_source_metadata(
        selected_sources=["nvd", "epss"],
        source_hashes={"nvd": "nvd-hash", "epss": "epss-hash"},
        source_counts={
            "nvd": {
                "records": 2,
                "fetched": 1,
                "fallback_from_previous_snapshot": 1,
                "missing": 0,
            }
        },
        cache_only=True,
    )

    assert metadata["nvd"] == {
        "source": "NVD CVE API 2.0",
        "record_count": 2,
        "fetched_count": 1,
        "fallback_from_previous_snapshot": 1,
        "missing_count": 0,
        "cache_only": True,
        "cache_namespace_hash": "nvd-hash",
    }
    assert metadata["epss"]["record_count"] == 0
    assert (
        _latest_nvd_sync(
            [
                NvdData(cve_id="CVE-1", published="2024-01-01", last_modified="2024-01-02"),
                NvdData(cve_id="CVE-2", published="2024-02-01"),
            ]
        )
        == "2024-02-01"
    )
    assert (
        _latest_epss_date(
            [
                EpssData(cve_id="CVE-1", date="2024-01-01"),
                EpssData(cve_id="CVE-2", date="2024-03-01"),
            ]
        )
        == "2024-03-01"
    )
    assert (
        _latest_kev_date(
            [
                KevData(cve_id="CVE-1", date_added="2024-01-01"),
                KevData(cve_id="CVE-2", date_added="2024-02-01"),
            ]
        )
        == "2024-02-01"
    )


def test_provider_update_failure_payloads_are_redacted_before_persistence() -> None:
    payload = _redacted_payload(
        {
            "detail": "failed while reading /Users/alice/.vpw/token-secret.txt",
            "requested_sources": ["nvd"],
        }
    )

    assert payload["requested_sources"] == ["nvd"]
    assert "/Users/" not in str(payload)
    assert "token-secret" not in str(payload)
