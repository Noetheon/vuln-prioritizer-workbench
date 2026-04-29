from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlmodel import Session
from utils.template_workbench import TemplateApiEnv, auth_headers


def test_template_provider_status_requires_auth(template_api_env: TemplateApiEnv) -> None:
    response = template_api_env.client.get("/api/v1/providers/status")

    assert response.status_code == 401


def test_template_provider_status_reports_missing_snapshot(
    template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(template_api_env.client)

    response = template_api_env.client.get("/api/v1/providers/status", headers=headers)

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "degraded"
    assert payload["snapshot_mode"] == "missing"
    assert payload["snapshot"]["missing"] is True
    assert payload["last_sync"] is None
    assert payload["cache_age_seconds"] is None
    assert payload["last_error"] is None
    assert "No provider snapshot has been recorded yet." in payload["warnings"]
    assert [source["name"] for source in payload["sources"]] == ["nvd", "epss", "kev"]
    assert all(source["available"] is False for source in payload["sources"])


def test_template_provider_status_reports_latest_snapshot(
    template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(template_api_env.client)
    snapshot_id = uuid.uuid4()
    created_at = datetime(2026, 4, 28, 10, 0, tzinfo=UTC)
    with Session(template_api_env.engine) as session:
        session.add(
            template_api_env.app_models.ProviderSnapshot(
                id=snapshot_id,
                created_at=created_at,
                nvd_last_sync="2026-04-28T10:15:00Z",
                epss_date="2026-04-28",
                kev_catalog_version="2026-04-27",
                content_hash="sha256:provider-status-fixture",
                source_hashes_json={"nvd": "sha256:nvd-feed"},
                source_metadata_json={
                    "selected_sources": ["nvd", "epss", "kev"],
                    "cache_only": True,
                    "requested_cves": 3,
                    "generated_at": "2026-04-28T10:30:00Z",
                    "snapshot_dir": "data/provider-snapshots",
                    "cache_dir": "data/provider-cache",
                },
            )
        )
        session.commit()

    response = template_api_env.client.get("/api/v1/providers/status", headers=headers)

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["snapshot_mode"] == "cache-only"
    assert payload["last_sync"] == "2026-04-28T10:30:00Z"
    assert isinstance(payload["cache_age_seconds"], int)
    assert payload["last_error"] is None
    assert payload["cache_dir"] == "data/provider-cache"
    assert payload["snapshot_dir"] == "data/provider-snapshots"
    assert payload["snapshot"] == {
        "id": str(snapshot_id),
        "created_at": "2026-04-28T10:00:00+00:00",
        "content_hash": "sha256:provider-status-fixture",
        "nvd_last_sync": "2026-04-28T10:15:00Z",
        "epss_date": "2026-04-28",
        "kev_catalog_version": "2026-04-27",
        "generated_at": "2026-04-28T10:30:00Z",
        "selected_sources": ["nvd", "epss", "kev"],
        "requested_cves": 3,
        "source_hashes": {"nvd": "sha256:nvd-feed"},
        "source_metadata": {
            "selected_sources": ["nvd", "epss", "kev"],
            "cache_only": True,
            "requested_cves": 3,
            "generated_at": "2026-04-28T10:30:00Z",
            "snapshot_dir": "data/provider-snapshots",
            "cache_dir": "data/provider-cache",
        },
        "source_path": None,
        "locked_provider_data": False,
        "missing": False,
        "mode": "cache-only",
    }
    sources = {source["name"]: source for source in payload["sources"]}
    assert sources["nvd"]["selected"] is True
    assert sources["nvd"]["available"] is True
    assert sources["nvd"]["last_sync"] == "2026-04-28T10:15:00Z"
    assert sources["epss"]["value"] == "2026-04-28"
    assert sources["kev"]["value"] == "2026-04-27"


def test_template_provider_status_surfaces_failed_provider_update(
    template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(template_api_env.client)
    with Session(template_api_env.engine) as session:
        repository = template_api_env.repositories.RunRepository(session)
        snapshot = repository.create_provider_snapshot(
            nvd_last_sync="2026-04-28T10:15:00Z",
            epss_date="2026-04-28",
            kev_catalog_version="2026-04-28",
            content_hash="sha256:provider-status-error-fixture",
            source_metadata_json={"selected_sources": ["nvd", "epss", "kev"]},
        )
        project = template_api_env.repositories.ProjectRepository(session).create_project(
            template_api_env.app_models.ProjectCreate(name="Provider Status Project"),
            owner_id=uuid.UUID("00000000-0000-4000-8000-000000000011"),
        )
        repository.create_analysis_run(
            project_id=project.id,
            input_type="provider_update",
            status=template_api_env.app_models.AnalysisRunStatus.FAILED,
            provider_snapshot_id=snapshot.id,
            summary_json={"requested_sources": ["nvd", "epss", "kev"]},
            error_json={"detail": "forced provider cache failure"},
        )
        session.commit()

    response = template_api_env.client.get("/api/v1/providers/status", headers=headers)

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "degraded"
    assert payload["latest_update_job"]["status"] == "failed"
    assert payload["latest_update_job"]["requested_sources"] == ["nvd", "epss", "kev"]
    assert payload["latest_update_job"]["error_message"] == "forced provider cache failure"
    assert payload["last_error"] == "forced provider cache failure"
    assert "Latest provider update failed: forced provider cache failure" in payload["warnings"]
    assert all(
        source["last_error"] == "forced provider cache failure" for source in payload["sources"]
    )
