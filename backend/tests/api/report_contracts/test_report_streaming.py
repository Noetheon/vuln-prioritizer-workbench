from __future__ import annotations

import gzip
import hashlib
import json
import uuid
from pathlib import Path

import pytest
from sqlmodel import Session, select
from utils.workbench_contracts import (
    _configure_report_dir,
    _create_report_via_worker,
    _seed_reportable_run,
)
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers

from app.models import AnalysisRun, Project, Report
from app.repositories.evidence_payloads import EvidencePayloadStore
from app.services.report_exports import render_analysis_result_json, render_findings_csv
from app.services.report_models import ReportGenerationError
from app.services.report_service_payload import ReportSource, build_report_payload
from app.services.report_service_persistence import persist_stream_report
from app.services.report_streaming import stream_analysis_json, stream_findings_csv
from app.services.workflow_execution import WorkflowCancellationRequested


def test_streamed_values_equal_existing_report_contract_with_batched_reads(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = workbench_api_env
    headers = local_api_headers(env.client)
    project_id = uuid.UUID(create_project_via_api(env.client, headers)["id"])
    run_id = _seed_reportable_run(env, project_id)
    with Session(env.engine) as session:
        run, project = session.get(AnalysisRun, run_id), session.get(Project, project_id)
        assert run is not None and project is not None
        expected, _, _ = build_report_payload(session, run=run, project=project)
        source = ReportSource(session, run=run, project=project)
        source.header = source.header.model_copy(update={"generated_at": expected.generated_at})
        source.batch_size = 1
        batches = []
        original = EvidencePayloadStore.load_records

        def track(store, records):
            rows = list(records)
            batches.append(len(rows))
            return original(store, rows)

        monkeypatch.setattr(EvidencePayloadStore, "load_records", track)
        checkpoints = []
        result = b"".join(stream_analysis_json(source, checkpoint=lambda: checkpoints.append(1)))
        assert json.loads(result) == json.loads(render_analysis_result_json(expected))
        assert batches == [1] * len(expected.findings)
        assert len(checkpoints) == len(batches)
        csv_source = ReportSource(session, run=run, project=project)
        assert b"".join(stream_findings_csv(csv_source)).decode() == render_findings_csv(expected)


def test_gzip_export_download_preserves_full_evidence_and_checksum(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    env = workbench_api_env
    _configure_report_dir(env, tmp_path)
    headers = local_api_headers(env.client)
    project_id = uuid.UUID(create_project_via_api(env.client, headers)["id"])
    run_id = _seed_reportable_run(env, project_id)
    report = _create_report_via_worker(
        env, run_id, headers=headers, payload={"format": "json-gzip"}
    )
    response = env.client.get(report["download_url"], headers=headers)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/gzip"
    assert report["filename"] == "analysis-result.v2.json.gz"
    assert hashlib.sha256(response.content).hexdigest() == report["sha256"]
    assert len(response.content) == report["size_bytes"]
    result = json.loads(gzip.decompress(response.content))
    with Session(env.engine) as session:
        run, project = session.get(AnalysisRun, run_id), session.get(Project, project_id)
        assert run is not None and project is not None
        expected, _, _ = build_report_payload(session, run=run, project=project)
    original = json.loads(render_analysis_result_json(expected))
    original["generated_at"] = result["generated_at"]
    original["governance_rollups"]["generated_at"] = result["governance_rollups"]["generated_at"]
    assert result == original


@pytest.mark.parametrize("failure", ["plain_size", "compressed_size", "expanded_size", "cancel"])
def test_stream_failure_stops_input_and_removes_partial_artifacts(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    failure: str,
) -> None:
    env = workbench_api_env
    root = _configure_report_dir(env, tmp_path, MAX_REPORT_MB=1)
    settings = env.client.app.state.workbench_settings
    headers = local_api_headers(env.client)
    project_id = uuid.UUID(create_project_via_api(env.client, headers)["id"])
    run_id = _seed_reportable_run(env, project_id)
    steps, closed = [], []

    def chunks():
        try:
            for _ in range(100):
                steps.append(1)
                if failure == "compressed_size":
                    # A deterministic high-entropy chunk avoids relying on gzip ratios.
                    yield b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(32769))
                elif failure == "cancel":
                    yield b"small"
                    return
                else:
                    yield b"x" * (1024 * 1024)
        finally:
            closed.append(True)

    def cancel():
        raise WorkflowCancellationRequested("cancel before publication")

    stream = chunks()
    with Session(env.engine) as session:
        run, project = session.get(AnalysisRun, run_id), session.get(Project, project_id)
        assert run is not None and project is not None
        with pytest.raises((ReportGenerationError, WorkflowCancellationRequested)):
            persist_stream_report(
                session,
                settings,
                run=run,
                project=project,
                generated_at=project.created_at,
                finding_count=2,
                provider_snapshot_id=None,
                chunks=stream,
                compress=failure in {"compressed_size", "expanded_size"},
                kind="analysis-result-json",
                report_format="json",
                filename="test.json",
                content_type="application/json",
                before_publication=cancel if failure == "cancel" else None,
            )
        assert session.exec(select(Report)).all() == []
    assert closed == [True]
    assert len(steps) <= 21
    assert not list(root.rglob("test.json"))


def test_whole_run_rendering_rejects_input_before_loading_next_batch(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = workbench_api_env
    headers = local_api_headers(env.client)
    project_id = uuid.UUID(create_project_via_api(env.client, headers)["id"])
    run_id = _seed_reportable_run(env, project_id)
    monkeypatch.setattr(ReportSource, "batch_size", 1)
    reads = []
    original = EvidencePayloadStore.load_records

    def track(store, records):
        rows = list(records)
        reads.append(len(rows))
        return original(store, rows)

    monkeypatch.setattr(EvidencePayloadStore, "load_records", track)
    with Session(env.engine) as session:
        run, project = session.get(AnalysisRun, run_id), session.get(Project, project_id)
        assert run is not None and project is not None
        with pytest.raises(ReportGenerationError, match="streaming JSON"):
            build_report_payload(session, run=run, project=project, max_input_bytes=1)
    assert reads == [1]
