"""Native reevaluation preserves observations and atomically appends real Ledger history."""

from __future__ import annotations

import hashlib
import json
import uuid
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import pytest
from sqlmodel import Session, select
from utils.import_contracts import completed_run_payload
from utils.workbench_contracts import _create_report_via_worker
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api

from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.decision_core.projection_evaluation import evaluate_evidence_payload
from app.domain.engine.models import WaiverRule
from app.domain.engine.services.prioritization import PrioritizationService
from app.models import (
    AnalysisRun,
    FindingDecisionEvidence,
    FindingOccurrence,
    ProviderSnapshot,
    WorkflowRun,
)
from app.repositories.current_projections import FindingCurrentProjectionRepository
from app.repositories.workflows import WorkflowRepository
from app.services import reevaluation_execution
from app.services.decision_projection_sync import DecisionProjectionService
from app.services.decision_scope_lock import lock_project_decision_scope
from app.services.evaluation_publication import publish_evaluation_run
from app.workers.workflow_worker import run_worker_once


def _import(
    env: WorkbenchApiEnv, tmp_path: Path, *, extra_rows: bytes = b""
) -> tuple[str, dict, dict]:
    settings = env.client.app.state.workbench_settings
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir(exist_ok=True)
    source = (
        Path(__file__).resolve().parents[2] / "app" / "resources" / "demo_provider_snapshot.json"
    )
    (snapshots / "demo.json").write_bytes(source.read_bytes())
    env.client.app.state.workbench_settings = replace(
        settings,
        PROVIDER_SNAPSHOT_DIR=str(snapshots),
        IMPORT_UPLOAD_DIR=str(tmp_path / "uploads"),
        REPORT_DIR=str(tmp_path / "reports"),
    )
    project = create_project_via_api(env.client, {}, name="Evaluation history")
    response = env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        data={
            "input_type": "generic-occurrence-csv",
            "provider_snapshot_file": "demo.json",
            "locked_provider_data": "true",
        },
        files={
            "file": (
                "observations.csv",
                (
                    b"cve_id,target_ref,asset_id,owner,business_service,exposure,environment,criticality\n"
                    b"CVE-2024-4577,web,web,owner,payments,internal,test,low\n" + extra_rows
                ),
                "text/csv",
            )
        },
    )
    assert response.status_code == 200, response.text
    run = completed_run_payload(env, response, headers={})
    assert run["status"] == "succeeded", run
    findings = env.client.get(f"/api/v1/projects/{project['id']}/findings/").json()["data"]
    detail = env.client.get(f"/api/v1/findings/{findings[0]['id']}").json()
    return project["id"], detail, run


def _worker(env: WorkbenchApiEnv):
    return run_worker_once(
        engine=env.engine,
        settings=env.client.app.state.workbench_settings,
        worker_id="native-evaluation-test",
        retry_delay_seconds=0,
    )


def test_one_scope_waiver_hydrates_and_revises_only_its_scope(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = file_backed_workbench_api_env
    project_id, selected, _ = _import(
        env,
        tmp_path,
        extra_rows=b"".join(
            f"CVE-2024-4577,peer-{index},peer-{index},owner,payments,internal,test,low\n".encode()
            for index in range(30)
        ),
    )
    finding_id = uuid.UUID(selected["id"])
    with Session(env.engine) as session:
        before = {
            row.id: deepcopy(row.payload_json)
            for row in session.exec(select(FindingDecisionEvidence)).all()
        }
    hydrated: list[uuid.UUID] = []
    evaluations: list[str] = []
    original_hydrate = FindingCurrentProjectionRepository.evidence_for_records
    original_prioritize = PrioritizationService.prioritize

    def hydrate(self, records, **kwargs):
        records = list(records)
        hydrated.extend(record.finding_id for record in records)
        return original_hydrate(self, records, **kwargs)

    def prioritize(self, cve_ids, **kwargs):
        evaluations.extend(cve_ids)
        return original_prioritize(self, cve_ids, **kwargs)

    monkeypatch.setattr(FindingCurrentProjectionRepository, "evidence_for_records", hydrate)
    monkeypatch.setattr(PrioritizationService, "prioritize", prioritize)
    response = env.client.post(
        f"/api/v1/projects/{project_id}/waivers/",
        json={
            "finding_id": str(finding_id),
            "owner": "risk-owner",
            "reason": "A bounded scope acceptance",
            "expires_at": "2099-12-31",
        },
    )
    assert response.status_code == 200, response.text
    assert hydrated == [finding_id]
    assert evaluations == [selected["cve_id"]]
    with Session(env.engine) as session:
        history = session.exec(select(FindingDecisionEvidence)).all()
        assert len(history) == len(before) + 1
        assert {row.id: row.payload_json for row in history if row.id in before} == before
        revision = next(row for row in history if row.id not in before)
        assert revision.finding_id == finding_id
        assert revision.payload_json["operational_rank"] == len(before)
        assert revision.payload_json["evaluation"]["cause"] == "waiver"
        hydrated.clear()
        evaluations.clear()
        lock_project_decision_scope(session, uuid.UUID(project_id))
        DecisionProjectionService(session).sync_project_waivers(
            uuid.UUID(project_id), force=True, revision_cause="waiver"
        )
        assert hydrated == []
        assert evaluations == []
        assert len(session.exec(select(FindingDecisionEvidence)).all()) == len(history)
        assert FindingCurrentProjectionRepository(session).verify_all_source_parity().matches


def test_native_evaluation_appends_history_without_observing_or_resetting_manual_status(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    env = file_backed_workbench_api_env
    project_id, before, _ = _import(env, tmp_path)
    finding_id = uuid.UUID(before["id"])
    with Session(env.engine) as session:
        old = session.exec(select(FindingDecisionEvidence)).one()
        original = deepcopy(old.payload_json)
        old_id = old.id
        observations = list(session.exec(select(FindingOccurrence.id)).all())
    status = env.client.patch(f"/api/v1/findings/{finding_id}/status", json={"status": "in_review"})
    assert status.status_code == 200, status.text
    queued = env.client.post(
        f"/api/v1/projects/{project_id}/evaluations", json={"reason": "Periodic review"}
    )
    assert queued.status_code == 200, queued.text
    assert queued.json()["input_type"] == "reevaluation"
    result = _worker(env)
    assert result.completed == 1, result
    after = env.client.get(f"/api/v1/findings/{finding_id}").json()
    assert after["status"] == "in_review"
    assert after["last_seen_at"] == before["last_seen_at"]
    assert after["risk_score"] == before["risk_score"]
    assert after["rationale"] == before["rationale"]
    assert after["evidence"]["evaluation"]["cause"] == "manual"
    with Session(env.engine) as session:
        assert session.get(FindingDecisionEvidence, old_id).payload_json == original
        assert list(session.exec(select(FindingOccurrence.id)).all()) == observations
        assert FindingCurrentProjectionRepository(session).verify_all_source_parity().matches
    revisions = env.client.get(f"/api/v1/findings/{finding_id}/decision-revisions").json()
    assert revisions["count"] == 2
    assert [item["is_current"] for item in revisions["data"]] == [True, False]
    assert revisions["data"][0]["replay_status"] == "available"
    assert "status" in revisions["data"][0]["changed_fields"]
    assert revisions["data"][0]["observed_at"] is not None
    listing = env.client.get(f"/api/v1/projects/{project_id}/evaluations").json()
    assert listing["count"] == 1
    assert listing["data"][0]["status"] == "completed"


def test_native_evaluation_consumes_asset_patch_without_separate_recalculate(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    env = file_backed_workbench_api_env
    project_id, before, _ = _import(env, tmp_path)
    patched = env.client.patch(
        f"/api/v1/assets/{before['asset_id']}",
        json={
            "owner": "new-owner",
            "criticality": "critical",
            "environment": "production",
            "exposure": "internet-facing",
        },
    )
    assert patched.status_code == 200
    response = env.client.post(f"/api/v1/projects/{project_id}/evaluations", json={})
    assert response.status_code == 200, response.text
    assert _worker(env).completed == 1
    after = env.client.get(f"/api/v1/findings/{before['id']}").json()
    assert after["risk_score"] > before["risk_score"]
    assert "new-owner" in after["rationale"]
    assert after["evidence"]["priority_evidence"]["raw"]["asset_context"]["rescore_needed"] is False
    assert after["last_seen_at"] == before["last_seen_at"]


def test_asset_recalculate_preserves_explicitly_cleared_context(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    env = file_backed_workbench_api_env
    _, before, _ = _import(env, tmp_path)
    response = env.client.patch(
        f"/api/v1/assets/{before['asset_id']}",
        json={
            "owner": None,
            "business_service": None,
        },
    )
    assert response.status_code == 200, response.text
    recalculated = env.client.post(f"/api/v1/assets/{before['asset_id']}/recalculate")
    assert recalculated.status_code == 200, recalculated.text
    after = env.client.get(f"/api/v1/findings/{before['id']}").json()
    observations = after["evidence"]["evaluation_input"]["observations"]
    assert all(item["asset_owner"] is None for item in observations)
    assert all(item["asset_business_service"] is None for item in observations)
    assert after["evidence"]["priority_evidence"]["raw"]["provenance"]["asset_owners"] == []


def test_native_asset_context_uses_the_shared_unknown_value_normalization(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    env = file_backed_workbench_api_env
    project_id, before, _ = _import(env, tmp_path)
    response = env.client.patch(
        f"/api/v1/assets/{before['asset_id']}",
        json={
            "owner": None,
            "business_service": None,
            "environment": "unknown",
            "exposure": "unknown",
            "criticality": "unknown",
        },
    )
    assert response.status_code == 200, response.text
    assert env.client.post(f"/api/v1/projects/{project_id}/evaluations", json={}).status_code == 200
    assert _worker(env).completed == 1
    after = env.client.get(f"/api/v1/findings/{before['id']}").json()
    for item in after["evidence"]["evaluation_input"]["observations"]:
        assert all(
            item[field] is None
            for field in (
                "asset_owner",
                "asset_business_service",
                "asset_environment",
                "asset_exposure",
                "asset_criticality",
            )
        )


def test_origin_waiver_expiry_restores_actionable_status_in_shared_evaluation(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _, before, _ = _import(file_backed_workbench_api_env, tmp_path)
    original = FindingDecisionEvidenceV2.model_validate(before["evidence"])
    assert original.evaluation_input is not None
    today = datetime.now(UTC).date()
    inputs = original.evaluation_input.model_copy(
        update={
            "evaluation_date": today,
            "waiver_rules": [
                WaiverRule(
                    cve_id=original.cve_id,
                    owner="risk-owner",
                    reason="Source waiver",
                    expires_on=today.isoformat(),
                )
            ],
        }
    )
    accepted, _ = evaluate_evidence_payload(original.to_jsonable(), inputs=inputs)
    assert accepted["status"] == "accepted" and accepted["waived"] is True
    expired, _ = evaluate_evidence_payload(
        accepted, inputs=inputs.model_copy(update={"evaluation_date": today + timedelta(days=1)})
    )
    assert expired["waived"] is False
    assert expired["status"] == "open"


def test_queued_evaluation_uses_execution_date_for_waiver_expiry(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = file_backed_workbench_api_env
    project_id, before, _ = _import(env, tmp_path)
    now = datetime.now(UTC)
    response = env.client.post(
        f"/api/v1/projects/{project_id}/waivers/",
        json={
            "finding_id": before["id"],
            "owner": "risk-owner",
            "reason": "Bounded exception",
            "expires_at": (now.date() + timedelta(days=1)).isoformat(),
        },
    )
    assert response.status_code == 200, response.text
    queued = env.client.post(f"/api/v1/projects/{project_id}/evaluations", json={})
    assert queued.status_code == 200, queued.text
    monkeypatch.setattr(reevaluation_execution, "get_datetime_utc", lambda: now + timedelta(days=2))
    assert _worker(env).completed == 1
    # Inspect persisted evidence directly so a read-side daily waiver refresh
    # cannot make the worker's publication appear correct after the fact.
    with Session(env.engine) as session:
        evidence = FindingCurrentProjectionRepository(session).get_evidence(uuid.UUID(before["id"]))
        assert evidence is not None and evidence.evaluation_input is not None
        assert evidence.waived is False
        assert evidence.status == "open"
        assert evidence.evaluation_input.evaluation_date == (now + timedelta(days=2)).date()


def test_native_evaluation_adopts_verified_provider_snapshot_and_rejects_tampering(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    env = file_backed_workbench_api_env
    project_id, before, _ = _import(env, tmp_path)
    artifact = tmp_path / "snapshots" / "updated.json"
    document = json.loads((tmp_path / "snapshots" / "demo.json").read_text())
    row = next(item for item in document["items"] if item["cve_id"] == "CVE-2024-4577")
    row["kev"]["in_kev"] = False
    row["epss"]["epss"] = 0.001
    artifact.write_text(json.dumps(document))
    with Session(env.engine) as session:
        snapshot = ProviderSnapshot(
            content_hash=hashlib.sha256(artifact.read_bytes()).hexdigest(),
            source_metadata_json={"snapshot_file": "updated.json"},
        )
        session.add(snapshot)
        session.commit()
        snapshot_id = str(snapshot.id)
    queued = env.client.post(
        f"/api/v1/projects/{project_id}/evaluations", json={"provider_snapshot_id": snapshot_id}
    )
    assert queued.status_code == 200, queued.text
    assert _worker(env).completed == 1
    after = env.client.get(f"/api/v1/findings/{before['id']}").json()
    assert after["epss"] == 0.001
    assert after["in_kev"] is False
    assert after["risk_score"] != before["risk_score"]
    assert after["evidence"]["provider"]["provider_snapshot_id"] == snapshot_id
    assert after["last_seen_at"] == before["last_seen_at"]
    artifact.write_text(artifact.read_text() + " ")
    rejected = env.client.post(
        f"/api/v1/projects/{project_id}/evaluations", json={"provider_snapshot_id": snapshot_id}
    )
    assert rejected.status_code == 409
    assert "content hash" in rejected.text


def test_native_evaluation_stale_publication_rolls_back_every_decision(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = file_backed_workbench_api_env
    project_id, before, _ = _import(env, tmp_path)
    queued = env.client.post(f"/api/v1/projects/{project_id}/evaluations", json={})
    assert queued.status_code == 200
    real_evaluate = reevaluation_execution.evaluate_evidence_payload

    def concurrent_edit(*args, **kwargs):
        result = real_evaluate(*args, **kwargs)
        with Session(env.engine) as competing:
            lock_project_decision_scope(competing, uuid.UUID(project_id))
            competing.commit()
        return result

    monkeypatch.setattr(reevaluation_execution, "evaluate_evidence_payload", concurrent_edit)
    assert _worker(env).retried_or_failed == 1
    with Session(env.engine) as session:
        assert len(session.exec(select(FindingDecisionEvidence)).all()) == 1
        run = session.get(AnalysisRun, uuid.UUID(queued.json()["id"]))
        assert run.status == "failed"
    after = env.client.get(f"/api/v1/findings/{before['id']}").json()
    assert after["evidence"] == before["evidence"]


def test_native_evaluation_rejects_legacy_and_cross_project_selection(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    env = file_backed_workbench_api_env
    project_id, before, _ = _import(env, tmp_path)
    other = create_project_via_api(env.client, {}, name="Unrelated")
    rejected = env.client.post(
        f"/api/v1/projects/{other['id']}/evaluations", json={"finding_ids": [before["id"]]}
    )
    assert rejected.status_code == 409
    with Session(env.engine) as session:
        projection = FindingCurrentProjectionRepository(session)
        payload = projection.current_payload(uuid.UUID(before["id"]))
        payload.pop("evaluation_input")
        payload.pop("evaluation", None)
        publish_evaluation_run(
            session,
            project_id=uuid.UUID(project_id),
            payloads={uuid.UUID(before["id"]): payload},
            cause="legacy_fixture",
        )
        session.commit()
    rejected = env.client.post(f"/api/v1/projects/{project_id}/evaluations", json={})
    assert rejected.status_code == 409
    assert "legacy_unavailable" in rejected.text


def test_native_evaluation_cancellation_from_another_connection_prevents_publication(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = file_backed_workbench_api_env
    project_id, before, _ = _import(env, tmp_path)
    queued = env.client.post(f"/api/v1/projects/{project_id}/evaluations", json={}).json()
    workflow_id = uuid.UUID(queued["workflow"]["id"])
    real_evaluate = reevaluation_execution.evaluate_evidence_payload

    def cancel_during_compute(*args, **kwargs):
        result = real_evaluate(*args, **kwargs)
        with Session(env.engine) as control:
            WorkflowRepository(control).request_cancel(workflow_id)
            control.commit()
        return result

    monkeypatch.setattr(reevaluation_execution, "evaluate_evidence_payload", cancel_during_compute)
    assert _worker(env).cancelled == 1
    with Session(env.engine) as session:
        assert session.get(WorkflowRun, workflow_id).status == "cancelled"
        assert len(session.exec(select(FindingDecisionEvidence)).all()) == 1
        assert (
            FindingCurrentProjectionRepository(session).current_payload(uuid.UUID(before["id"]))
            == FindingDecisionEvidenceV2.model_validate(before["evidence"]).to_jsonable()
        )


def test_native_history_is_monotonic_with_a_fixed_clock(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WORKBENCH_FIXED_NOW", "2026-06-06T10:00:00+00:00")
    env = file_backed_workbench_api_env
    project_id, before, imported = _import(env, tmp_path)
    run_ids = [imported["id"]]
    for index in range(3):
        queued = env.client.post(
            f"/api/v1/projects/{project_id}/evaluations", json={"reason": f"Review {index}"}
        )
        assert queued.status_code == 200, queued.text
        run_ids.append(queued.json()["id"])
        assert _worker(env).completed == 1
        revisions = env.client.get(f"/api/v1/findings/{before['id']}/decision-revisions").json()
        assert [item["analysis_run_id"] for item in revisions["data"]] == list(reversed(run_ids))
        assert [item["is_current"] for item in revisions["data"]] == [True] + [False] * (index + 1)
        assert {item["observed_at"] for item in revisions["data"]} == {"2026-06-06T10:00:00Z"}


def test_selected_snapshot_change_reranks_peer_without_replacing_its_facts(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    env = file_backed_workbench_api_env
    project_id, _, _ = _import(
        env,
        tmp_path,
        extra_rows=b"CVE-2024-4577,critical-web,critical-web,owner,payments,internet-facing,production,critical\n",
    )
    before = env.client.get(
        f"/api/v1/projects/{project_id}/findings/", params={"include_evidence": True}
    ).json()["data"]
    selected, peer = sorted(before, key=lambda item: item["operational_rank"])
    assert selected["risk_score"] > peer["risk_score"]
    with Session(env.engine) as session:
        original_peer = session.exec(
            select(FindingDecisionEvidence).where(
                FindingDecisionEvidence.finding_id == uuid.UUID(peer["id"])
            )
        ).one()
        peer_source_id = original_peer.id
        peer_source_payload = deepcopy(original_peer.payload_json)
    artifact = tmp_path / "snapshots" / "lower.json"
    document = json.loads((tmp_path / "snapshots" / "demo.json").read_text())
    item = next(row for row in document["items"] if row["cve_id"] == selected["cve_id"])
    item["nvd"]["cvss_base_score"] = 0.1
    item["epss"]["epss"] = 0.0001
    item["kev"]["in_kev"] = False
    artifact.write_text(json.dumps(document))
    with Session(env.engine) as session:
        snapshot = ProviderSnapshot(
            content_hash=hashlib.sha256(artifact.read_bytes()).hexdigest(),
            source_metadata_json={"snapshot_file": "lower.json"},
        )
        session.add(snapshot)
        session.commit()
        snapshot_id = str(snapshot.id)
    queued = env.client.post(
        f"/api/v1/projects/{project_id}/evaluations",
        json={"finding_ids": [selected["id"]], "provider_snapshot_id": snapshot_id},
    )
    assert queued.status_code == 200, queued.text
    assert _worker(env).completed == 1
    after = env.client.get(f"/api/v1/findings/{peer['id']}").json()
    assert after["operational_rank"] == 1
    assert after["risk_score"] == peer["risk_score"]
    assert after["rationale"] == peer["rationale"]
    assert after["evidence"]["provider"] == peer["evidence"]["provider"]
    assert after["evidence"]["evaluation_input"] == peer["evidence"]["evaluation_input"]
    assert "#1" in after["evidence"]["remediation"]["decision_statement"]
    with Session(env.engine) as session:
        peer_history = session.exec(
            select(FindingDecisionEvidence).where(
                FindingDecisionEvidence.finding_id == uuid.UUID(peer["id"])
            )
        ).all()
        assert len(peer_history) == 1
        assert peer_history[0].id == peer_source_id
        assert peer_history[0].payload_json == peer_source_payload
        assert FindingCurrentProjectionRepository(session).verify_all_source_parity().matches


def test_native_evaluation_report_exports_its_recorded_decision_without_new_upload(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    env = file_backed_workbench_api_env
    project_id, before, _ = _import(env, tmp_path)
    queued = env.client.post(f"/api/v1/projects/{project_id}/evaluations", json={}).json()
    assert _worker(env).completed == 1
    report = _create_report_via_worker(
        env, uuid.UUID(queued["id"]), headers={}, payload={"format": "zip"}
    )
    response = env.client.get(report["download_url"])
    assert response.status_code == 200
    with ZipFile(BytesIO(response.content)) as bundle:
        analysis = json.loads(bundle.read("analysis.json"))
        manifest = json.loads(bundle.read("manifest.json"))
        assert analysis["analysis_run"]["id"] == queued["id"]
        assert len(analysis["findings"]) == 1
        assert analysis["findings"][0]["cve_id"] == before["cve_id"]
        assert analysis["findings"][0]["risk_score"] == before["risk_score"]
        assert analysis["findings"][0]["recommendation"]["rationale"] == before["rationale"]
        assert analysis["provider_snapshot"]["id"] is not None
        for item in manifest["files"]:
            assert item["sha256"] == hashlib.sha256(bundle.read(item["path"])).hexdigest()


def test_daily_refresh_expires_source_file_waiver_without_upload(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = file_backed_workbench_api_env
    project_id, before, _ = _import(env, tmp_path)
    finding_id = uuid.UUID(before["id"])
    with Session(env.engine) as session:
        evidence = FindingCurrentProjectionRepository(session).get_evidence(finding_id)
        assert evidence is not None and evidence.evaluation_input is not None
        today = evidence.evaluation_input.evaluation_date
        source_rule = WaiverRule(
            id="origin-file",
            cve_id=evidence.cve_id,
            owner="risk",
            reason="Source policy",
            expires_on=today.isoformat(),
        )
        accepted_input = evidence.evaluation_input.model_copy(
            update={"waiver_rules": [source_rule]}
        )
        payload, _ = evaluate_evidence_payload(evidence.to_jsonable(), inputs=accepted_input)
        lock_project_decision_scope(session, uuid.UUID(project_id))
        publish_evaluation_run(
            session,
            project_id=uuid.UUID(project_id),
            payloads={finding_id: payload},
            cause="source_file",
        )
        session.commit()
    monkeypatch.setenv("WORKBENCH_FIXED_NOW", f"{today + timedelta(days=1)}T12:00:00+00:00")
    pending = env.client.get(f"/api/v1/findings/{finding_id}")
    assert pending.status_code == 503
    assert _worker(env).refreshed_projects == 1
    detail = env.client.get(f"/api/v1/findings/{finding_id}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["waived"] is False
    assert detail.json()["status"] == "open"
    revisions = env.client.get(f"/api/v1/findings/{finding_id}/decision-revisions").json()["data"]
    assert len(revisions) == 3
    assert revisions[0]["cause"] == "waiver_expiry"
    assert revisions[0]["is_current"] is True
