from __future__ import annotations

import json
import uuid
from dataclasses import replace
from pathlib import Path

from sqlmodel import Session, select
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response

from app import models as app_models
from app.core.config import Settings
from app.main import _upload_size_guard
from app.workers.workflow_worker import run_worker_once
from utils.import_contract_fixtures import PROJECT_ROOT
from utils.workbench_env import WorkbenchApiEnv


def configure_upload_dir(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    *,
    max_upload_mb: int = 25,
) -> Path:
    upload_dir = tmp_path / "workbench-import-uploads"
    active_settings = workbench_api_env.client.app.state.workbench_settings
    workbench_api_env.client.app.state.workbench_settings = replace(
        active_settings,
        IMPORT_UPLOAD_DIR=str(upload_dir),
        PROVIDER_SNAPSHOT_DIR=str(PROJECT_ROOT / "data"),
        ATTACK_ARTIFACT_DIR=str(PROJECT_ROOT / "data" / "attack"),
        DEMO_PROVIDER_SNAPSHOT_ENABLED=True,
        MAX_UPLOAD_MB=max_upload_mb,
    )
    return upload_dir.resolve(strict=False)


async def run_upload_size_guard(
    messages: list[dict[str, object]],
    *,
    api_prefix: str = "/api/v1",
    max_request_body_mb: int = 2,
    route_suffix: str = "/imports",
) -> Response:
    app = Starlette()
    app.state.workbench_settings = Settings(
        MAX_REQUEST_BODY_MB=max_request_body_mb,
        MAX_UPLOAD_MB=1,
        API_V1_STR=api_prefix,
    )
    message_iter = iter(messages)

    async def receive() -> dict[str, object]:
        return next(message_iter)

    request = Request(
        {
            "app": app,
            "client": ("testclient", 50000),
            "headers": [],
            "method": "POST",
            "path": f"{api_prefix}/projects/{uuid.uuid4()}{route_suffix}",
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
            "type": "http",
        },
        receive,
    )

    async def call_next(streamed_request: Request) -> Response:
        await streamed_request.body()
        return Response("accepted")

    return await _upload_size_guard(request, call_next)


def assert_no_sensitive_path_leak(payload: object, *paths: Path) -> None:
    text = json.dumps(payload, sort_keys=True)
    forbidden_fragments = [
        "/Users/",
        "/private/",
        "/tmp/",
        "/var/",
        "\\Users\\",
    ]
    for path in paths:
        forbidden_fragments.append(str(path))
    for fragment in forbidden_fragments:
        assert fragment not in text


def run_count(workbench_api_env: WorkbenchApiEnv, project_id: uuid.UUID) -> int:
    with Session(workbench_api_env.engine) as session:
        return len(
            workbench_api_env.repositories.RunRepository(session).list_analysis_runs(project_id)
        )


def drain_workflow_queue(
    workbench_api_env: WorkbenchApiEnv,
    *,
    max_ticks: int = 20,
    retry_delay_seconds: int = 0,
) -> None:
    settings = workbench_api_env.client.app.state.workbench_settings
    for tick in range(max_ticks):
        result = run_worker_once(
            engine=workbench_api_env.engine,
            settings=settings,
            worker_id=f"test-worker-{tick}",
            limit=1,
            retry_delay_seconds=retry_delay_seconds,
        )
        if result.claimed == 0:
            return
    raise AssertionError("workflow queue did not drain")


def public_run_aliases(payload: dict[str, object]) -> dict[str, object]:
    evidence = payload.get("evidence")
    evidence_payload = evidence if isinstance(evidence, dict) else {}
    aliases = {
        "asset_context",
        "vex",
        "dedup_summary",
        "analysis_service",
        "analysis_semantics",
        "input_sha256",
        "warnings",
    }
    diagnostics = payload.get("diagnostics")
    diagnostic_aliases = diagnostics if isinstance(diagnostics, dict) else {}
    alias_payload = {key: evidence_payload[key] for key in aliases if key in evidence_payload}
    if "schema_version" in evidence_payload:
        alias_payload["workflow_schema_version"] = evidence_payload["schema_version"]
    counts = evidence_payload.get("counts")
    if not isinstance(counts, dict):
        counts = payload.get("counts")
    if isinstance(counts, dict):
        for key in (
            "attack_mapped_cves",
            "suppressed_by_vex",
            "created_findings",
            "updated_findings",
            "ignored_lines",
            "rows_read",
            "occurrence_count",
            "finding_count",
            "counts_by_priority",
            "kev_hits",
            "epss_hits",
            "nvd_hits",
            "under_investigation_count",
            "vex_conflict_count",
        ):
            if key in counts:
                alias_payload[key] = counts[key]
    uploads = evidence_payload.get("uploads")
    if not isinstance(uploads, dict):
        uploads = payload.get("uploads")
    if isinstance(uploads, dict):
        alias_payload["input_upload"] = uploads.get("input")
        alias_payload["asset_context_upload"] = uploads.get("asset_context")
        alias_payload["vex_upload"] = uploads.get("vex")
    provider = evidence_payload.get("provider")
    if not isinstance(provider, dict):
        provider = payload.get("provider_snapshot")
    if isinstance(provider, dict):
        for key in (
            "provider_snapshot_file",
            "provider_snapshot_hash",
            "provider_snapshot_id",
            "locked_provider_data",
            "provider_data_quality_flags",
            "provider_degraded",
        ):
            if key in provider:
                alias_payload[key] = provider[key]
    attack = evidence_payload.get("attack")
    if isinstance(attack, dict):
        alias_payload["attack_source"] = attack.get("source")
    if "parse_errors" in payload:
        alias_payload["parse_errors"] = payload["parse_errors"]
    if diagnostic_aliases:
        alias_payload["workflow_error"] = diagnostic_aliases
    return {
        **alias_payload,
        **diagnostic_aliases,
        **payload,
    }


def completed_run_payload(
    workbench_api_env: WorkbenchApiEnv,
    response: object,
    *,
    headers: dict[str, str],
) -> dict[str, object]:
    assert getattr(response, "status_code") == 200, getattr(response, "text")
    run_id = response.json()["id"]
    drain_workflow_queue(workbench_api_env)
    run = workbench_api_env.client.get(f"/api/v1/runs/{run_id}", headers=headers)
    assert run.status_code == 200, run.text
    return public_run_aliases(run.json())


def completed_run_summary(
    workbench_api_env: WorkbenchApiEnv,
    response_or_run_id: object,
    *,
    headers: dict[str, str],
) -> dict[str, object]:
    if isinstance(response_or_run_id, str):
        run_id = response_or_run_id
    else:
        assert getattr(response_or_run_id, "status_code") == 200, getattr(
            response_or_run_id, "text"
        )
        run_id = response_or_run_id.json()["id"]
    drain_workflow_queue(workbench_api_env)
    summary = workbench_api_env.client.get(f"/api/v1/runs/{run_id}/summary", headers=headers)
    assert summary.status_code == 200, summary.text
    return public_run_aliases(summary.json())


def finding_state(
    workbench_api_env: WorkbenchApiEnv,
    project_id: uuid.UUID,
) -> tuple[list[app_models.Finding], int]:
    with Session(workbench_api_env.engine) as session:
        findings = list(
            session.exec(
                select(app_models.Finding)
                .where(app_models.Finding.project_id == project_id)
                .order_by(app_models.Finding.cve_id)
            )
        )
        occurrence_count = len(
            session.exec(
                select(app_models.FindingOccurrence)
                .join(app_models.Finding)
                .where(app_models.Finding.project_id == project_id)
            ).all()
        )
        return findings, occurrence_count


def decision_state(findings: list[app_models.Finding]) -> dict[str, dict[str, object]]:
    values: dict[str, dict[str, object]] = {}
    for finding in findings:
        values[finding.cve_id] = {
            "priority": str(finding.priority),
            "priority_rank": finding.priority_rank,
            "risk_score": finding.risk_score,
            "operational_rank": finding.operational_rank,
            "rationale": finding.rationale,
            "recommended_action": finding.recommended_action,
        }
    return values
