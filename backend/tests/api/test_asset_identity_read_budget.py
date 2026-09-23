"""Identity validation scales with distinct facts, not findings times history."""

from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import event
from sqlmodel import Session, select
from utils.import_contracts import completed_run_payload
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api

from app.models import Asset, FindingOccurrence
from app.repositories.assets import AssetRepository


def test_shared_asset_reimports_read_distinct_identity_once_per_pass(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = file_backed_workbench_api_env
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    snapshots.joinpath("demo.json").write_bytes(
        (
            Path(__file__).resolve().parents[2] / "app/resources/demo_provider_snapshot.json"
        ).read_bytes()
    )
    env.client.app.state.workbench_settings = replace(
        env.client.app.state.workbench_settings, PROVIDER_SNAPSHOT_DIR=str(snapshots)
    )
    project = create_project_via_api(env.client, {})
    count = 30
    content = (
        "cve_id,target_ref\n"
        + "".join(f"CVE-2021-44228,target-{index}\n" for index in range(count))
    ).encode()
    sidecar = (
        "target_kind,target_ref,asset_id\n"
        + "".join(f"generic,target-{index},shared-asset\n" for index in range(count))
    ).encode()
    counters: Counter[str] = Counter()
    original = AssetRepository._iter_asset_occurrence_evidence
    identity_reads: list[tuple[str, tuple]] = []

    def counted(repository, asset_id):
        counters["calls"] += 1
        for value in original(repository, asset_id):
            counters["rows"] += 1
            assert set(value) == {"asset_id", "target_kind", "target_ref"}
            yield value

    def observed(_connection, _cursor, statement, parameters, _context, _many):
        if statement.startswith("SELECT DISTINCT CAST(JSON_QUOTE(JSON_EXTRACT(finding_occurrence."):
            identity_reads.append((statement, parameters))

    monkeypatch.setattr(AssetRepository, "_iter_asset_occurrence_evidence", counted)
    event.listen(env.engine, "before_cursor_execute", observed)
    try:
        for number in range(3):
            counters.clear()
            response = env.client.post(
                f"/api/v1/projects/{project['id']}/imports",
                data={
                    "input_type": "generic-occurrence-csv",
                    "provider_snapshot_file": "demo.json",
                    "locked_provider_data": "true",
                },
                files={
                    "file": ("scopes.csv", content, "text/csv"),
                    "asset_context_file": ("assets.csv", sidecar, "text/csv"),
                },
            )
            run = completed_run_payload(env, response, headers={})
            assert run["status"] == "succeeded", run
            if number:
                assert counters["calls"] <= 2
                assert counters["rows"] <= 2 * count
        assert identity_reads
        statement, parameters = identity_reads[-1]
        with env.engine.connect() as connection:
            plan = connection.exec_driver_sql("EXPLAIN QUERY PLAN " + statement, parameters).all()
            assert any("ix_finding_occurrence_identity" in row[-1] for row in plan), plan
    finally:
        event.remove(env.engine, "before_cursor_execute", observed)
    with Session(env.engine) as session:
        asset = session.exec(
            select(Asset).where(Asset.project_id == uuid.UUID(project["id"]))
        ).one()
        assert len(session.exec(select(FindingOccurrence)).all()) == 3 * count
        repository = AssetRepository(session)
        assert repository.asset_matches_import_identity(
            asset, asset_id="shared-asset", target_kind="generic", target_ref="target-0"
        )
        # Even an older contradictory value is found. The database index follows
        # the original JSON; there is no stale cached identity certificate.
        occurrence = session.exec(select(FindingOccurrence)).first()
        assert occurrence is not None
        occurrence.evidence_json = dict(occurrence.evidence_json, asset_id=123)
        session.add(occurrence)
        session.flush()
        assert not repository.asset_matches_import_identity(
            asset, asset_id="shared-asset", target_kind="generic", target_ref="target-0"
        )
