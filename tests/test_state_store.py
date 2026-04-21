from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import vuln_prioritizer.state_store as state_store_module
from vuln_prioritizer.state_store import SQLiteStateStore


def test_state_store_import_is_idempotent_for_identical_snapshot_bytes(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    snapshot_path = _write_snapshot_file(
        tmp_path,
        "snapshot.json",
        _snapshot_payload(
            "2026-04-10T09:00:00+00:00",
            [_finding("CVE-2024-1001", priority_label="High", priority_rank=2)],
        ),
    )
    store = SQLiteStateStore(db_path)

    first = store.import_snapshot(
        snapshot_path=snapshot_path,
        payload=json.loads(snapshot_path.read_text(encoding="utf-8")),
    )
    second = store.import_snapshot(
        snapshot_path=snapshot_path,
        payload=json.loads(snapshot_path.read_text(encoding="utf-8")),
    )

    assert first["imported"] is True
    assert second["imported"] is False
    assert first["snapshot_id"] == second["snapshot_id"]
    assert store.snapshot_count() == 1


def test_state_store_history_returns_newest_snapshot_first(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    before_path = _write_snapshot_file(
        tmp_path,
        "before.json",
        _snapshot_payload(
            "2026-04-10T09:00:00+00:00",
            [
                _finding(
                    "CVE-2024-2002",
                    priority_label="High",
                    priority_rank=2,
                    in_kev=False,
                    services=["identity"],
                    asset_ids=["asset-app-01"],
                )
            ],
        ),
    )
    after_path = _write_snapshot_file(
        tmp_path,
        "after.json",
        _snapshot_payload(
            "2026-04-20T09:00:00+00:00",
            [
                _finding(
                    "CVE-2024-2002",
                    priority_label="Critical",
                    priority_rank=1,
                    in_kev=True,
                    services=["identity"],
                    asset_ids=["asset-app-02"],
                )
            ],
        ),
    )
    store = SQLiteStateStore(db_path)
    store.import_snapshot(
        snapshot_path=before_path,
        payload=json.loads(before_path.read_text(encoding="utf-8")),
    )
    store.import_snapshot(
        snapshot_path=after_path,
        payload=json.loads(after_path.read_text(encoding="utf-8")),
    )

    history = store.cve_history(cve_id="CVE-2024-2002")

    assert [entry["priority_label"] for entry in history] == ["Critical", "High"]
    assert [entry["in_kev"] for entry in history] == [True, False]
    assert [entry["asset_ids"] for entry in history] == [["asset-app-02"], ["asset-app-01"]]


def test_state_store_waiver_filters_respect_status_and_latest_scope(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    first_path = _write_snapshot_file(
        tmp_path,
        "waivers-before.json",
        _snapshot_payload(
            "2026-04-10T09:00:00+00:00",
            [
                _finding(
                    "CVE-2024-3001",
                    priority_label="High",
                    priority_rank=2,
                    waived=True,
                    waiver_owner="risk-review",
                    waiver_expires_on="2026-06-01",
                )
            ],
        ),
    )
    latest_path = _write_snapshot_file(
        tmp_path,
        "waivers-latest.json",
        _snapshot_payload(
            "2026-04-20T09:00:00+00:00",
            [
                _finding(
                    "CVE-2024-3002",
                    priority_label="High",
                    priority_rank=2,
                    waived=True,
                    waiver_status="review_due",
                    waiver_owner="team-app",
                    waiver_review_on="2026-04-19",
                    waiver_expires_on="2026-05-15",
                ),
                _finding(
                    "CVE-2024-3003",
                    priority_label="Critical",
                    priority_rank=1,
                    waived=False,
                    waiver_status="expired",
                    waiver_owner="team-sec",
                    waiver_expires_on="2026-04-01",
                    waiver_days_remaining=-10,
                ),
            ],
        ),
    )
    store = SQLiteStateStore(db_path)
    store.import_snapshot(
        snapshot_path=first_path,
        payload=json.loads(first_path.read_text(encoding="utf-8")),
    )
    store.import_snapshot(
        snapshot_path=latest_path,
        payload=json.loads(latest_path.read_text(encoding="utf-8")),
    )

    latest_entries = store.waiver_entries(status_filter="all", latest_only=True)
    active_entries = store.waiver_entries(status_filter="active", latest_only=False)
    review_due_entries = store.waiver_entries(status_filter="review_due", latest_only=False)
    expired_entries = store.waiver_entries(status_filter="expired", latest_only=False)

    assert [entry["cve_id"] for entry in latest_entries] == ["CVE-2024-3003", "CVE-2024-3002"]
    assert [entry["cve_id"] for entry in active_entries] == ["CVE-2024-3001"]
    assert [entry["cve_id"] for entry in review_due_entries] == ["CVE-2024-3002"]
    assert [entry["cve_id"] for entry in expired_entries] == ["CVE-2024-3003"]


def test_state_store_waiver_latest_only_uses_newest_generated_snapshot_for_out_of_order_imports(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.db"
    newest_generated_path = _write_snapshot_file(
        tmp_path,
        "waivers-newest-generated.json",
        _snapshot_payload(
            "2026-04-20T09:00:00+00:00",
            [
                _finding(
                    "CVE-2024-3010",
                    priority_label="High",
                    priority_rank=2,
                    waived=True,
                    waiver_status="review_due",
                    waiver_owner="team-app",
                    waiver_review_on="2026-04-19",
                )
            ],
        ),
    )
    older_generated_path = _write_snapshot_file(
        tmp_path,
        "waivers-older-generated.json",
        _snapshot_payload(
            "2026-04-10T09:00:00+00:00",
            [
                _finding(
                    "CVE-2024-3009",
                    priority_label="Critical",
                    priority_rank=1,
                    waived=True,
                    waiver_owner="team-sec",
                    waiver_expires_on="2026-05-01",
                )
            ],
        ),
    )
    store = SQLiteStateStore(db_path)
    store.import_snapshot(
        snapshot_path=newest_generated_path,
        payload=json.loads(newest_generated_path.read_text(encoding="utf-8")),
    )
    store.import_snapshot(
        snapshot_path=older_generated_path,
        payload=json.loads(older_generated_path.read_text(encoding="utf-8")),
    )

    latest_entries = store.waiver_entries(status_filter="all", latest_only=True)

    assert [entry["cve_id"] for entry in latest_entries] == ["CVE-2024-3010"]
    assert [entry["snapshot_generated_at"] for entry in latest_entries] == [
        "2026-04-20T09:00:00+00:00"
    ]


def test_state_store_top_services_aggregates_across_recent_snapshots(
    monkeypatch,
    tmp_path: Path,
) -> None:
    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: ANN206
            return cls(2026, 4, 30, 12, 0, 0, tzinfo=tz or UTC)

    monkeypatch.setattr(state_store_module, "datetime", FrozenDateTime)

    db_path = tmp_path / "state.db"
    first_path = _write_snapshot_file(
        tmp_path,
        "services-before.json",
        _snapshot_payload(
            "2026-04-10T09:00:00+00:00",
            [
                _finding(
                    "CVE-2024-4001",
                    priority_label="Critical",
                    priority_rank=1,
                    in_kev=True,
                    services=["identity", "payments"],
                ),
                _finding(
                    "CVE-2024-4002",
                    priority_label="High",
                    priority_rank=2,
                    services=["identity"],
                ),
                _finding(
                    "CVE-2024-4003",
                    priority_label="Medium",
                    priority_rank=3,
                    services=[],
                ),
            ],
        ),
    )
    second_path = _write_snapshot_file(
        tmp_path,
        "services-after.json",
        _snapshot_payload(
            "2026-04-20T09:00:00+00:00",
            [
                _finding(
                    "CVE-2024-4001",
                    priority_label="Critical",
                    priority_rank=1,
                    in_kev=True,
                    services=["identity", "payments"],
                )
            ],
        ),
    )
    store = SQLiteStateStore(db_path)
    store.import_snapshot(
        snapshot_path=first_path,
        payload=json.loads(first_path.read_text(encoding="utf-8")),
    )
    store.import_snapshot(
        snapshot_path=second_path,
        payload=json.loads(second_path.read_text(encoding="utf-8")),
    )

    services = store.top_services(days=30, priority_filter="all", limit=10)

    assert [entry["service"] for entry in services] == ["identity", "payments", "Unmapped"]
    assert services[0]["occurrence_count"] == 3
    assert services[0]["distinct_cves"] == 2
    assert services[0]["snapshot_count"] == 2
    assert services[0]["kev_count"] == 2
    assert services[1]["occurrence_count"] == 2
    assert services[2]["occurrence_count"] == 1


def _write_snapshot_file(tmp_path: Path, name: str, payload: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _snapshot_payload(generated_at: str, findings: list[dict]) -> dict:
    return {
        "metadata": {
            "snapshot_kind": "snapshot",
            "generated_at": generated_at,
            "input_format": "cve-list",
            "input_path": "fixtures/cves.txt",
        },
        "findings": findings,
    }


def _finding(
    cve_id: str,
    *,
    priority_label: str,
    priority_rank: int,
    in_kev: bool = False,
    services: list[str] | None = None,
    asset_ids: list[str] | None = None,
    waived: bool = False,
    waiver_status: str | None = None,
    waiver_owner: str | None = None,
    waiver_expires_on: str | None = None,
    waiver_review_on: str | None = None,
    waiver_days_remaining: int | None = None,
) -> dict:
    return {
        "cve_id": cve_id,
        "priority_label": priority_label,
        "priority_rank": priority_rank,
        "in_kev": in_kev,
        "attack_mapped": False,
        "attack_relevance": "Unmapped",
        "waived": waived,
        "waiver_status": waiver_status,
        "waiver_owner": waiver_owner,
        "waiver_expires_on": waiver_expires_on,
        "waiver_review_on": waiver_review_on,
        "waiver_days_remaining": waiver_days_remaining,
        "provenance": {
            "asset_ids": asset_ids or [],
            "occurrences": [{"asset_business_service": service} for service in (services or [])],
        },
    }
