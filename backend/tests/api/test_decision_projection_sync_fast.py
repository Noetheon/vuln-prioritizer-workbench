from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlmodel import Session, select
from utils.import_contracts import drain_workflow_queue
from utils.workbench_env import WorkbenchApiEnv, local_api_headers
from utils.workbench_workflow_contracts import configure_workflow_context, post_import

from app.domain.engine.services.prioritization import PrioritizationService
from app.models import Finding, FindingCurrentProjection, FindingDecisionEvidence
from app.repositories.current_projections import FindingCurrentProjectionRepository
from app.services.decision_projection_sync_fast import sync_unchanged_project_ranks


def _import_scopes(env: WorkbenchApiEnv, tmp_path: Path) -> uuid.UUID:
    context = configure_workflow_context(env, tmp_path)
    imported = post_import(
        env,
        context,
        data={
            "input_type": "generic-occurrence-csv",
            "provider_snapshot_file": "demo_provider_snapshot.json",
            "locked_provider_data": "true",
        },
        files={
            "file": (
                "scopes.csv",
                b"cve_id,target_ref,exposure,environment,criticality\n"
                b"CVE-2021-44228,z-existing,internet-facing,production,critical\n"
                b"CVE-2021-44228,a-first,internal,test,low\n",
                "text/csv",
            )
        },
    )
    assert imported["status"] == "succeeded"
    return uuid.UUID(context.project_id)


def test_rank_fast_path_preserves_inputs_and_history_and_skips_unchanged_writes(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = file_backed_workbench_api_env
    project_id = _import_scopes(env, tmp_path)
    with Session(env.engine) as session:
        repository = FindingCurrentProjectionRepository(session)
        records = list(session.exec(select(FindingCurrentProjection)).all())
        evidence = repository.evidence_for_records(records)
        expected = {key: item.to_jsonable() for key, item in evidence.items()}
        original_sources = {
            source.id: source.payload_json
            for source in repository.source_records_for_records(records).values()
        }
        # A prior rank overlay is valid current state; convergence must restore
        # only its ranks/guidance without changing a single canonical input.
        for record in records:
            payload = evidence[record.finding_id].to_jsonable()
            payload["operational_rank"] += 10
            payload["priority_evidence"]["raw"]["operational_rank"] += 10
            repository.update_current_payload(record.finding_id, payload)
        assert sync_unchanged_project_ranks(session, project_id)
        actual = repository.evidence_for_records(records)
        assert {key: item.to_jsonable() for key, item in actual.items()} == expected
        assert {
            source.id: source.payload_json
            for source in repository.source_records_for_records(records).values()
        } == original_sources
        assert repository.verify_source_parity(records).matches

        def unexpected_write(*_args: Any, **_kwargs: Any) -> None:
            pytest.fail("An unchanged queue must not rewrite any current decision")

        monkeypatch.setattr(
            FindingCurrentProjectionRepository, "update_current_payload", unexpected_write
        )
        monkeypatch.setattr(
            FindingCurrentProjectionRepository, "evidence_for_records", unexpected_write
        )
        assert sync_unchanged_project_ranks(session, project_id)


def test_migrated_queue_keys_are_reconstructed_once_without_changing_history(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = file_backed_workbench_api_env
    project_id = _import_scopes(env, tmp_path)
    with Session(env.engine) as session:
        repository = FindingCurrentProjectionRepository(session)
        records = list(session.exec(select(FindingCurrentProjection)).all())
        expected = repository.evidence_for_records(records)
        for record in records:
            record.operational_sort_key_json = None
            session.add(record)
        session.flush()
        assert sync_unchanged_project_ranks(session, project_id)
        assert all(record.operational_sort_key_json is not None for record in records)
        assert repository.evidence_for_records(records) == expected
        assert repository.verify_source_parity(records).matches

        def unexpected_hydration(*_args: Any, **_kwargs: Any) -> None:
            pytest.fail("Persisted queue keys must avoid subsequent evidence hydration")

        monkeypatch.setattr(
            FindingCurrentProjectionRepository, "evidence_for_records", unexpected_hydration
        )
        assert sync_unchanged_project_ranks(session, project_id)


def test_rank_fast_path_declines_stale_context_before_modifying_any_projection(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    env = file_backed_workbench_api_env
    project_id = _import_scopes(env, tmp_path)
    with Session(env.engine) as session:
        repository = FindingCurrentProjectionRepository(session)
        records = list(session.exec(select(FindingCurrentProjection)).all())
        payload = repository.current_payload(records[-1].finding_id)
        assert payload is not None
        payload["priority_evidence"]["data_quality_flags"].append(
            {
                "source": "asset_context",
                "code": "asset_context_rescore_needed",
                "message": "Asset context changed since this evaluation.",
                "severity": "warning",
            }
        )
        repository.update_current_payload(records[-1].finding_id, payload)
        before = {row.finding_id: row.model_dump() for row in records}
        assert sync_unchanged_project_ranks(session, project_id) is False
        assert {row.finding_id: row.model_dump() for row in records} == before
        assert len(session.exec(select(Finding)).all()) == 2


def test_incremental_import_evaluates_only_new_scope_and_updates_displaced_ranks(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = file_backed_workbench_api_env
    project_id = _import_scopes(env, tmp_path)
    with Session(env.engine) as session:
        existing_ids = set(session.exec(select(Finding.id)).all())
        original_projections = {
            row.finding_id: (
                row.source_finding_evidence_id,
                row.lifecycle_overlay_json,
                row.projection_payload_sha256,
                row.lifecycle_revision,
            )
            for row in session.exec(select(FindingCurrentProjection)).all()
        }
        history_ids = set(session.exec(select(FindingDecisionEvidence.id)).all())
    evaluations: list[str] = []
    rank_updates: list[uuid.UUID] = []
    original_prioritize = PrioritizationService.prioritize
    original_update = FindingCurrentProjectionRepository.update_queue_ranks

    def prioritize(self: PrioritizationService, cve_ids: list[str], **kwargs: Any) -> Any:
        evaluations.extend(cve_ids)
        return original_prioritize(self, cve_ids, **kwargs)

    def update_rank(
        self: FindingCurrentProjectionRepository,
        ranks: dict[uuid.UUID, int],
        **kwargs: Any,
    ) -> Any:
        rank_updates.extend(ranks)
        return original_update(self, ranks, **kwargs)

    def unexpected_evidence_write(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("Displacing a peer must not copy its decision evidence")

    monkeypatch.setattr(PrioritizationService, "prioritize", prioritize)
    monkeypatch.setattr(FindingCurrentProjectionRepository, "update_queue_ranks", update_rank)
    monkeypatch.setattr(
        FindingCurrentProjectionRepository, "update_current_payload", unexpected_evidence_write
    )
    queued = env.client.post(
        f"/api/v1/projects/{project_id}/imports",
        headers=local_api_headers(env.client),
        data={
            "input_type": "generic-occurrence-csv",
            "provider_snapshot_file": "demo_provider_snapshot.json",
            "locked_provider_data": "true",
        },
        files={
            "file": (
                "incremental.csv",
                b"cve_id,target_ref,exposure,environment,criticality\n"
                b"CVE-2021-44228,a-new,internet-facing,production,critical\n",
                "text/csv",
            )
        },
    )
    assert queued.status_code == 200
    drain_workflow_queue(env)
    assert evaluations == ["CVE-2021-44228"]
    assert set(rank_updates) == existing_ids
    assert len(rank_updates) == 2
    with Session(env.engine) as session:
        repository = FindingCurrentProjectionRepository(session)
        records = session.exec(select(FindingCurrentProjection)).all()
        assert {
            row.finding_id: (
                row.source_finding_evidence_id,
                row.lifecycle_overlay_json,
                row.projection_payload_sha256,
                row.lifecycle_revision,
            )
            for row in records
            if row.finding_id in existing_ids
        } == original_projections
        assert (
            set(
                session.exec(
                    select(FindingDecisionEvidence.id).where(
                        FindingDecisionEvidence.finding_id.in_(existing_ids)
                    )
                ).all()
            )
            == history_ids
        )
        current = repository.evidence_for_records(records)
        assert sorted(item.operational_rank for item in current.values()) == [1, 2, 3]
        for item in current.values():
            assert item.remediation.decision_statement.startswith(
                f"Top finding #{item.operational_rank}:"
            )
        assert repository.verify_source_parity(records).matches
