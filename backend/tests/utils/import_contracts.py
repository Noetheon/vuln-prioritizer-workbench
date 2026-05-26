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
        explanation = finding.explanation_json.get("explanation", {})
        guidance = finding.explanation_json.get("decision_guidance", {})
        values[finding.cve_id] = {
            "priority": str(finding.priority),
            "priority_rank": finding.priority_rank,
            "risk_score": finding.risk_score,
            "operational_rank": finding.operational_rank,
            "reason_codes": tuple(explanation.get("reason_codes", [])),
            "decision_recommendation": guidance.get("recommendation"),
        }
    return values
