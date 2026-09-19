from __future__ import annotations

import hashlib
import io
import json
import uuid
import zipfile
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from sqlmodel import Session, select
from utils.import_contracts import (
    assert_no_sensitive_path_leak,
    completed_run_payload,
    drain_workflow_queue,
    run_count,
)
from utils.sbom_fixtures import configure_scanner, sbom_content, vulnerability_match
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers

from app.models import (
    AnalysisEvidence,
    Finding,
    FindingDecisionEvidence,
    FindingOccurrence,
    WorkflowRun,
)
from app.repositories import WorkflowRepository


def _initial_scan(
    env: WorkbenchApiEnv, tmp_path: Path, *, sidecars: bool = False
) -> tuple[Path, dict[str, str], dict[str, Any]]:
    root = configure_scanner(env, tmp_path, [vulnerability_match()])
    headers = local_api_headers(env.client)
    project = create_project_via_api(env.client, headers)
    files = {"file": ("inventory.json", sbom_content(), "application/json")}
    if sidecars:
        files["asset_context_file"] = (
            "context.csv",
            b"target_kind,target_ref,asset_id,owner,criticality,exposure,environment\n"
            b"sbom,orders-service@1,orders,security,critical,public,prod\n",
            "text/csv",
        )
        files["vex_file"] = (
            "vex.json",
            json.dumps(
                {
                    "@context": "https://openvex.dev/ns/v0.2.0",
                    "@id": "https://example.com/vex/rescan",
                    "author": "Test",
                    "timestamp": "2026-09-19T00:00:00Z",
                    "version": 1,
                    "statements": [
                        {
                            "vulnerability": {"name": "CVE-2021-44228"},
                            "products": [{"@id": vulnerability_match()["artifact"]["purl"]}],
                            "status": "affected",
                            "action_statement": "Upgrade this component.",
                        }
                    ],
                }
            ).encode(),
            "application/json",
        )
    response = env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={
            "input_type": "cyclonedx-json",
            "sbom_scanner": "grype",
            "sbom_target_ref": "orders-service@1",
            "sbom_db_update": "false",
        },
        files=files,
    )
    run = completed_run_payload(env, response, headers=headers)
    assert run["status"] == "succeeded", json.dumps(run, indent=2)
    return root, headers, run


def _rescan(env: WorkbenchApiEnv, run_id: str, headers: dict[str, str]) -> dict[str, Any]:
    response = env.client.post(
        f"/api/v1/runs/{run_id}/sbom-rescans", headers=headers, json={"sbom_db_update": False}
    )
    assert response.status_code == 202, response.text
    queued = response.json()
    assert queued["id"] != run_id
    assert queued["status"] == "pending"
    with Session(env.engine) as session:
        workflow = session.exec(
            select(WorkflowRun).where(WorkflowRun.analysis_run_id == uuid.UUID(queued["id"]))
        ).one()
        assert workflow.payload_json["sbom_db_update"] is False
        assert workflow.payload_json["sbom_source_run_id"] == run_id
    drain_workflow_queue(env)
    response = env.client.get(f"/api/v1/runs/{queued['id']}", headers=headers)
    assert response.status_code == 200, response.text
    run = response.json()
    assert run["status"] == "succeeded", json.dumps(run, indent=2)
    return run


def test_rescan_preserves_source_scope_observation_and_sidecars_without_closing_findings(
    workbench_api_env: WorkbenchApiEnv, tmp_path: Path
) -> None:
    env = workbench_api_env
    root, headers, original = _initial_scan(env, tmp_path, sidecars=True)
    initial_evidence = deepcopy(original["evidence"])
    assessment = initial_evidence["sbom_assessment"]
    with Session(env.engine) as session:
        finding = session.exec(select(Finding)).one()
        initial_finding = (
            finding.id,
            finding.dedup_key,
            finding.first_seen_at,
            finding.last_seen_at,
            finding.status,
        )
    rescanned = _rescan(env, original["id"], headers)
    evidence = rescanned["evidence"]
    new_assessment = evidence["sbom_assessment"]
    assert new_assessment["source_run_id"] == original["id"]
    assert new_assessment["target_ref"] == assessment["target_ref"]
    assert new_assessment["observed_at"] == assessment["observed_at"]
    assert new_assessment["scanned_at"] > assessment["scanned_at"]
    for name in ("input", "asset_context", "vex"):
        old_upload = initial_evidence["uploads"][name]
        new_upload = evidence["uploads"][name]
        assert new_upload["sha256"] == old_upload["sha256"]
        assert new_upload["storage_ref"] != old_upload["storage_ref"]
        assert (root / new_upload["storage_ref"]).read_bytes() == (
            root / old_upload["storage_ref"]
        ).read_bytes()
    configure_scanner(env, tmp_path, [])
    no_matches = _rescan(env, rescanned["id"], headers)
    assert no_matches["evidence"]["sbom_assessment"]["scanner_match_count"] == 0
    assert no_matches["evidence"]["sbom_assessment"]["observed_at"] == assessment["observed_at"]
    with Session(env.engine) as session:
        finding = session.exec(select(Finding)).one()
        assert (
            finding.id,
            finding.dedup_key,
            finding.first_seen_at,
            finding.last_seen_at,
            finding.status,
        ) == initial_finding
        occurrences = session.exec(select(FindingOccurrence)).all()
        assert len(occurrences) == 2
        assert {row.finding_id for row in occurrences} == {finding.id}
        decisions = session.exec(select(FindingDecisionEvidence)).all()
        assert len(decisions) == 2
        assert {row.payload_json["evaluation"]["observed_at"] for row in decisions} == {
            assessment["observed_at"]
        }
    previous = env.client.get(f"/api/v1/runs/{original['id']}", headers=headers)
    assert previous.json()["evidence"] == initial_evidence


def test_sbom_evidence_download_contains_verified_original_bytes_and_portable_checksums(
    workbench_api_env: WorkbenchApiEnv, tmp_path: Path
) -> None:
    env = workbench_api_env
    root, headers, run = _initial_scan(env, tmp_path)
    url = f"/api/v1/runs/{run['id']}/sbom-evidence"
    response = env.client.get(url, headers=headers)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/zip"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-disposition"].endswith(f'sbom-evidence-{run["id"]}.zip"')
    assert env.client.get(url, headers=headers).content == response.content
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert set(archive.namelist()) == {
            "sbom.json",
            "grype-report.json",
            "assessment.json",
            "manifest.json",
        }
        assert archive.read("sbom.json") == sbom_content()
        assessment = run["evidence"]["sbom_assessment"]
        assert (
            archive.read("grype-report.json")
            == (root / assessment["artifact_refs"]["report"]).read_bytes()
        )
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["analysis_run_id"] == run["id"]
        assert manifest["assessment"] == assessment
        assert json.loads(archive.read("assessment.json")) == assessment
        for item in manifest["files"]:
            content = archive.read(item["path"])
            assert item["sha256"] == hashlib.sha256(content).hexdigest()
            assert item["size_bytes"] == len(content)


@pytest.mark.parametrize("artifact", ["input", "report", "manifest"])
def test_download_rejects_modified_evidence_without_leaking_paths(
    workbench_api_env: WorkbenchApiEnv, tmp_path: Path, artifact: str
) -> None:
    env = workbench_api_env
    root, headers, run = _initial_scan(env, tmp_path)
    path = root / run["evidence"]["sbom_assessment"]["artifact_refs"][artifact]
    path.write_bytes(b"{}")
    response = env.client.get(f"/api/v1/runs/{run['id']}/sbom-evidence", headers=headers)
    assert response.status_code == 409, response.text
    assert_no_sensitive_path_leak(response.json(), root, path)


@pytest.mark.parametrize("artifact", ["input", "asset_context", "vex"])
def test_rescan_rejects_modified_source_or_sidecars_before_creating_run(
    workbench_api_env: WorkbenchApiEnv, tmp_path: Path, artifact: str
) -> None:
    env = workbench_api_env
    root, headers, run = _initial_scan(env, tmp_path, sidecars=True)
    path = root / run["evidence"]["uploads"][artifact]["storage_ref"]
    path.write_bytes(b"tampered")
    response = env.client.post(f"/api/v1/runs/{run['id']}/sbom-rescans", headers=headers)
    assert response.status_code == 409, response.text
    assert_no_sensitive_path_leak(response.json(), root, path)
    assert run_count(env, uuid.UUID(run["project_id"])) == 1


def test_first_committed_import_is_claimable_only_with_complete_scanner_options(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = file_backed_workbench_api_env
    root = configure_scanner(env, tmp_path, [])
    headers = local_api_headers(env.client)
    project = create_project_via_api(env.client, headers)
    original_commit = Session.commit
    observed: list[dict[str, object]] = []

    def inspect_first_commit(session: Session) -> None:
        original_commit(session)
        if observed or session.get_bind() is not env.engine:
            return
        # A real worker connection can claim immediately after the first commit.
        with Session(env.engine) as worker:
            claimed = WorkflowRepository(worker).claim_due_workflows(worker_id="queue-probe")
            assert len(claimed) == 1
            workflow = claimed[0]
            payload = deepcopy(workflow.payload_json)
            observed.append(payload)
            assert payload == {
                "run_id": str(workflow.analysis_run_id),
                "input_type": "cyclonedx-json",
                "provider_snapshot_file": None,
                "locked_provider_data": False,
                "attack_source": "none",
                "attack_mapping_file": None,
                "attack_technique_metadata_file": None,
                "sbom_scanner": "grype",
                "sbom_target_ref": "orders-service@1",
                "sbom_db_update": False,
                "sbom_source_run_id": None,
                "sbom_observed_at": None,
            }
            assert workflow.max_attempts == 3
            stored = root / project["id"] / str(workflow.analysis_run_id) / "inventory.json"
            assert stored.read_bytes() == sbom_content()
            worker.rollback()

    monkeypatch.setattr(Session, "commit", inspect_first_commit)
    response = env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={
            "input_type": "cyclonedx-json",
            "sbom_scanner": "grype",
            "sbom_target_ref": "orders-service@1",
            "sbom_db_update": "false",
        },
        files={"file": ("inventory.json", sbom_content(), "application/json")},
    )
    assert response.status_code == 200, response.text
    assert len(observed) == 1


@pytest.mark.parametrize("reference", ["absolute", "traversal", "foreign_run", "symlink"])
def test_evidence_paths_are_confined_to_the_recorded_run(
    workbench_api_env: WorkbenchApiEnv, tmp_path: Path, reference: str
) -> None:
    env = workbench_api_env
    root, headers, run = _initial_scan(env, tmp_path)
    original = root / run["evidence"]["sbom_assessment"]["artifact_refs"]["input"]
    outside = tmp_path / "private-inventory.json"
    outside.write_bytes(original.read_bytes())
    if reference == "symlink":
        original.unlink()
        original.symlink_to(outside)
    else:
        if reference == "absolute":
            invalid_ref = str(outside)
        elif reference == "traversal":
            invalid_ref = "../private-inventory.json"
        else:
            foreign = root / run["project_id"] / str(uuid.uuid4()) / "inventory.json"
            foreign.parent.mkdir(parents=True)
            foreign.write_bytes(original.read_bytes())
            invalid_ref = str(foreign.relative_to(root))
        # Corrupt persisted references to exercise defense against stale/untrusted storage data.
        with Session(env.engine) as session:
            record = session.exec(select(AnalysisEvidence)).one()
            payload = deepcopy(record.payload_json)
            payload["uploads"]["input"]["storage_ref"] = invalid_ref
            payload["uploads"]["input"]["path"] = invalid_ref
            payload["sbom_assessment"]["artifact_refs"]["input"] = invalid_ref
            record.payload_json = payload
            session.add(record)
            session.commit()
    for method, suffix in (("get", "sbom-evidence"), ("post", "sbom-rescans")):
        response = getattr(env.client, method)(
            f"/api/v1/runs/{run['id']}/{suffix}", headers=headers
        )
        assert response.status_code == 409, response.text
        assert_no_sensitive_path_leak(response.json(), outside, root)
    assert run_count(env, uuid.UUID(run["project_id"])) == 1
