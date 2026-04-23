from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from _cli_helpers import install_fake_providers as _install_fake_providers
from typer.testing import CliRunner

import vuln_prioritizer.state_store as state_store_module
from vuln_prioritizer.cli import app

runner = CliRunner()


def test_cli_state_init_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"

    first = runner.invoke(app, ["state", "init", "--db", str(db_path)])
    second = runner.invoke(app, ["state", "init", "--db", str(db_path)])

    assert first.exit_code == 0
    assert second.exit_code == 0
    assert db_path.exists()


def test_cli_state_import_snapshot_reports_duplicate_imports(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    output_file = tmp_path / "import.json"
    duplicate_file = tmp_path / "import-duplicate.json"
    snapshot_file = _write_snapshot_file(
        tmp_path,
        "snapshot.json",
        _snapshot_payload(
            "2026-04-10T09:00:00+00:00",
            [_finding("CVE-2024-1001", priority_label="High", priority_rank=2)],
        ),
    )

    first = runner.invoke(
        app,
        [
            "state",
            "import-snapshot",
            "--db",
            str(db_path),
            "--input",
            str(snapshot_file),
            "--format",
            "json",
            "--output",
            str(output_file),
        ],
    )
    second = runner.invoke(
        app,
        [
            "state",
            "import-snapshot",
            "--db",
            str(db_path),
            "--input",
            str(snapshot_file),
            "--format",
            "json",
            "--output",
            str(duplicate_file),
        ],
    )

    assert first.exit_code == 0
    assert second.exit_code == 0
    first_payload = json.loads(output_file.read_text(encoding="utf-8"))
    second_payload = json.loads(duplicate_file.read_text(encoding="utf-8"))
    assert first_payload["summary"]["imported"] is True
    assert first_payload["summary"]["finding_count"] == 1
    assert first_payload["summary"]["snapshot_id"] == 1
    assert second_payload["summary"]["imported"] is False
    assert second_payload["summary"]["snapshot_id"] == 1


def test_cli_state_history_returns_json_in_newest_first_order(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    output_file = tmp_path / "history.json"
    store = state_store_module.SQLiteStateStore(db_path)
    before_path = _write_snapshot_file(
        tmp_path,
        "before.json",
        _snapshot_payload(
            "2026-04-10T09:00:00+00:00",
            [_finding("CVE-2024-2002", priority_label="High", priority_rank=2, services=["edge"])],
        ),
    )
    after_path = _write_snapshot_file(
        tmp_path,
        "after.json",
        _snapshot_payload(
            "2026-04-20T09:00:00+00:00",
            [_finding("CVE-2024-2002", priority_label="Critical", priority_rank=1, in_kev=True)],
        ),
    )
    store.import_snapshot(
        snapshot_path=before_path,
        payload=json.loads(before_path.read_text(encoding="utf-8")),
    )
    store.import_snapshot(
        snapshot_path=after_path,
        payload=json.loads(after_path.read_text(encoding="utf-8")),
    )

    result = runner.invoke(
        app,
        [
            "state",
            "history",
            "--db",
            str(db_path),
            "--cve",
            "CVE-2024-2002",
            "--format",
            "json",
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["cve_id"] == "CVE-2024-2002"
    assert [item["priority_label"] for item in payload["items"]] == ["Critical", "High"]


def test_cli_state_waivers_filters_latest_snapshot_entries(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    output_file = tmp_path / "waivers.json"
    store = state_store_module.SQLiteStateStore(db_path)
    first_path = _write_snapshot_file(
        tmp_path,
        "waivers-before.json",
        _snapshot_payload(
            "2026-04-10T09:00:00+00:00",
            [_finding("CVE-2024-3001", priority_label="High", priority_rank=2, waived=True)],
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
                )
            ],
        ),
    )
    store.import_snapshot(
        snapshot_path=first_path,
        payload=json.loads(first_path.read_text(encoding="utf-8")),
    )
    store.import_snapshot(
        snapshot_path=latest_path,
        payload=json.loads(latest_path.read_text(encoding="utf-8")),
    )

    result = runner.invoke(
        app,
        [
            "state",
            "waivers",
            "--db",
            str(db_path),
            "--status",
            "review_due",
            "--latest-only",
            "--format",
            "json",
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["latest_only"] is True
    assert payload["metadata"]["status_filter"] == "review_due"
    assert [item["cve_id"] for item in payload["items"]] == ["CVE-2024-3002"]


def test_cli_state_waivers_latest_only_uses_newest_generated_snapshot_for_out_of_order_imports(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.db"
    output_file = tmp_path / "waivers-latest-only.json"
    store = state_store_module.SQLiteStateStore(db_path)
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
                )
            ],
        ),
    )
    older_generated_path = _write_snapshot_file(
        tmp_path,
        "waivers-older-generated.json",
        _snapshot_payload(
            "2026-04-10T09:00:00+00:00",
            [_finding("CVE-2024-3009", priority_label="Critical", priority_rank=1, waived=True)],
        ),
    )
    store.import_snapshot(
        snapshot_path=newest_generated_path,
        payload=json.loads(newest_generated_path.read_text(encoding="utf-8")),
    )
    store.import_snapshot(
        snapshot_path=older_generated_path,
        payload=json.loads(older_generated_path.read_text(encoding="utf-8")),
    )

    result = runner.invoke(
        app,
        [
            "state",
            "waivers",
            "--db",
            str(db_path),
            "--latest-only",
            "--format",
            "json",
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["latest_only"] is True
    assert [item["cve_id"] for item in payload["items"]] == ["CVE-2024-3010"]
    assert [item["snapshot_generated_at"] for item in payload["items"]] == [
        "2026-04-20T09:00:00+00:00"
    ]


def test_cli_state_top_services_supports_priority_filtered_json_output(
    monkeypatch,
    tmp_path: Path,
) -> None:
    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: ANN206
            return cls(2026, 4, 30, 12, 0, 0, tzinfo=tz or UTC)

    monkeypatch.setattr(state_store_module, "datetime", FrozenDateTime)

    db_path = tmp_path / "state.db"
    output_file = tmp_path / "top-services.json"
    store = state_store_module.SQLiteStateStore(db_path)
    snapshot_path = _write_snapshot_file(
        tmp_path,
        "services.json",
        _snapshot_payload(
            "2026-04-20T09:00:00+00:00",
            [
                _finding(
                    "CVE-2024-4001",
                    priority_label="Critical",
                    priority_rank=1,
                    services=["identity", "payments"],
                ),
                _finding(
                    "CVE-2024-4002",
                    priority_label="High",
                    priority_rank=2,
                    services=["identity"],
                ),
            ],
        ),
    )
    store.import_snapshot(
        snapshot_path=snapshot_path,
        payload=json.loads(snapshot_path.read_text(encoding="utf-8")),
    )

    result = runner.invoke(
        app,
        [
            "state",
            "top-services",
            "--db",
            str(db_path),
            "--days",
            "15",
            "--priority",
            "high",
            "--limit",
            "5",
            "--format",
            "json",
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["priority_filter"] == "high"
    assert [item["service"] for item in payload["items"]] == ["identity"]
    assert payload["items"][0]["occurrence_count"] == 1


def test_cli_state_trends_and_service_history_return_json(
    monkeypatch,
    tmp_path: Path,
) -> None:
    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: ANN206
            return cls(2026, 4, 30, 12, 0, 0, tzinfo=tz or UTC)

    monkeypatch.setattr(state_store_module, "datetime", FrozenDateTime)

    db_path = tmp_path / "state.db"
    store = state_store_module.SQLiteStateStore(db_path)
    before_path = _write_snapshot_file(
        tmp_path,
        "before.json",
        _snapshot_payload(
            "2026-04-10T09:00:00+00:00",
            [
                _finding(
                    "CVE-2024-5001",
                    priority_label="High",
                    priority_rank=2,
                    services=["payments"],
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
                    "CVE-2024-5001",
                    priority_label="Critical",
                    priority_rank=1,
                    in_kev=True,
                    services=["payments"],
                ),
                _finding(
                    "CVE-2024-5002",
                    priority_label="High",
                    priority_rank=2,
                    services=["identity"],
                ),
            ],
        ),
    )
    store.import_snapshot(
        snapshot_path=before_path,
        payload=json.loads(before_path.read_text(encoding="utf-8")),
    )
    store.import_snapshot(
        snapshot_path=after_path,
        payload=json.loads(after_path.read_text(encoding="utf-8")),
    )

    trends_result = runner.invoke(
        app,
        [
            "state",
            "trends",
            "--db",
            str(db_path),
            "--days",
            "30",
            "--format",
            "json",
        ],
    )
    service_result = runner.invoke(
        app,
        [
            "state",
            "service-history",
            "--db",
            str(db_path),
            "--service",
            "payments",
            "--days",
            "30",
            "--format",
            "json",
        ],
    )

    assert trends_result.exit_code == 0
    assert service_result.exit_code == 0
    trends_payload = json.loads(trends_result.stdout)
    service_payload = json.loads(service_result.stdout)
    assert [item["findings_count"] for item in trends_payload["items"]] == [1, 2]
    assert trends_payload["items"][1]["critical_count"] == 1
    assert service_payload["metadata"]["service"] == "payments"
    assert [item["distinct_cves"] for item in service_payload["items"]] == [1, 1]
    assert service_payload["items"][1]["kev_count"] == 1


def test_cli_state_round_trip_imports_cli_snapshot_and_queries_history_and_top_services(
    monkeypatch,
    tmp_path: Path,
) -> None:
    fixture_root = Path(__file__).resolve().parents[1] / "data" / "input_fixtures"
    db_path = tmp_path / "state.db"
    snapshot_file = tmp_path / "snapshot.json"
    import_file = tmp_path / "import.json"
    history_file = tmp_path / "history.json"
    top_services_file = tmp_path / "top-services.json"
    asset_context_file = tmp_path / "assets.csv"
    waiver_file = tmp_path / "waivers.yml"
    asset_context_file.write_text(
        "\n".join(
            [
                "target_kind,target_ref,asset_id,criticality,exposure,environment,owner,business_service",
                "host,app-01.example.internal,payments-api,high,internal,prod,team-payments,payments",
                "host,app-02.example.internal,identity-api,critical,internet-facing,prod,team-identity,identity",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    waiver_file.write_text(
        "\n".join(
            [
                "waivers:",
                "  - id: waiver-1",
                "    cve_id: CVE-2023-34362",
                "    owner: risk-review",
                "    reason: Deferred until the coordinated service restart.",
                "    expires_on: 2027-12-31",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _install_fake_providers(monkeypatch)

    snapshot_result = runner.invoke(
        app,
        [
            "snapshot",
            "create",
            "--input",
            str(fixture_root / "openvas_report.xml"),
            "--input-format",
            "openvas-xml",
            "--asset-context",
            str(asset_context_file),
            "--waiver-file",
            str(waiver_file),
            "--output",
            str(snapshot_file),
            "--format",
            "json",
        ],
    )

    assert snapshot_result.exit_code == 0

    import_result = runner.invoke(
        app,
        [
            "state",
            "import-snapshot",
            "--db",
            str(db_path),
            "--input",
            str(snapshot_file),
            "--output",
            str(import_file),
            "--format",
            "json",
        ],
    )

    assert import_result.exit_code == 0
    import_payload = json.loads(import_file.read_text(encoding="utf-8"))
    assert import_payload["summary"]["imported"] is True
    assert import_payload["summary"]["finding_count"] == 3

    history_result = runner.invoke(
        app,
        [
            "state",
            "history",
            "--db",
            str(db_path),
            "--cve",
            "CVE-2023-34362",
            "--output",
            str(history_file),
            "--format",
            "json",
        ],
    )

    assert history_result.exit_code == 0
    history_payload = json.loads(history_file.read_text(encoding="utf-8"))
    assert history_payload["metadata"]["cve_id"] == "CVE-2023-34362"
    assert len(history_payload["items"]) == 1
    assert set(history_payload["items"][0]["services"]) == {"identity", "payments"}

    top_services_result = runner.invoke(
        app,
        [
            "state",
            "top-services",
            "--db",
            str(db_path),
            "--days",
            "3650",
            "--output",
            str(top_services_file),
            "--format",
            "json",
        ],
    )

    assert top_services_result.exit_code == 0
    top_services_payload = json.loads(top_services_file.read_text(encoding="utf-8"))
    services = {item["service"]: item for item in top_services_payload["items"]}
    assert {"identity", "payments"} <= set(services)
    assert services["identity"]["occurrence_count"] == 3
    assert services["payments"]["occurrence_count"] == 1


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
            "output_format": "json",
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
    waived: bool = False,
    waiver_status: str | None = None,
) -> dict:
    return {
        "cve_id": cve_id,
        "priority_label": priority_label,
        "priority_rank": priority_rank,
        "rationale": f"{priority_label} test rationale",
        "recommended_action": "Review and remediate according to policy.",
        "in_kev": in_kev,
        "attack_mapped": False,
        "attack_relevance": "Unmapped",
        "waived": waived,
        "waiver_status": waiver_status,
        "waiver_owner": None,
        "waiver_expires_on": None,
        "waiver_review_on": None,
        "waiver_days_remaining": None,
        "provenance": {
            "asset_ids": [],
            "occurrences": [
                {
                    "cve_id": cve_id,
                    "source_format": "cve-list",
                    "asset_business_service": service,
                }
                for service in (services or [])
            ],
        },
    }
