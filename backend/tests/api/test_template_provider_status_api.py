from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from sqlmodel import Session
from utils.template_workbench import TemplateApiEnv, auth_headers

from vuln_prioritizer.models import (
    KevData,
    ProviderSnapshotItem,
    ProviderSnapshotMetadata,
    ProviderSnapshotReport,
)
from vuln_prioritizer.provider_snapshot import (
    generate_provider_snapshot_json,
    load_provider_snapshot,
)


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
                    "stale_sources": ["epss"],
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
            "stale_sources": ["epss"],
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
    assert sources["nvd"]["stale"] is False
    assert isinstance(sources["nvd"]["cache_age_seconds"], int)
    assert sources["nvd"]["last_sync"] == "2026-04-28T10:15:00Z"
    assert sources["epss"]["value"] == "2026-04-28"
    assert sources["epss"]["stale"] is True
    assert sources["kev"]["value"] == "2026-04-27"


def test_template_provider_status_does_not_treat_null_source_hash_as_available(
    template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(template_api_env.client)
    with Session(template_api_env.engine) as session:
        session.add(
            template_api_env.app_models.ProviderSnapshot(
                id=uuid.uuid4(),
                created_at=datetime(2026, 4, 28, 10, 0, tzinfo=UTC),
                content_hash="sha256:null-source-hashes",
                source_hashes_json={
                    "nvd": None,
                    "epss": None,
                    "kev": None,
                    "attack_stix": None,
                },
                source_metadata_json={
                    "selected_sources": ["nvd", "epss", "kev", "attack_stix"],
                    "generated_at": "2026-04-28T10:30:00Z",
                },
            )
        )
        session.commit()

    response = template_api_env.client.get("/api/v1/providers/status", headers=headers)

    assert response.status_code == 200
    sources = {source["name"]: source for source in response.json()["sources"]}
    assert sources["nvd"]["available"] is False
    assert sources["epss"]["available"] is False
    assert sources["kev"]["available"] is False
    assert sources["attack_stix"]["available"] is False


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


def test_template_provider_update_job_create_list_and_status(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    headers = auth_headers(template_api_env.client)
    active_settings = template_api_env.client.app.state.template_settings
    snapshot_dir = tmp_path / "template-provider-snapshots"
    cache_dir = tmp_path / "template-provider-cache"
    template_api_env.client.app.state.template_settings = replace(
        active_settings,
        PROVIDER_SNAPSHOT_DIR=str(snapshot_dir),
        PROVIDER_CACHE_DIR=str(cache_dir),
    )
    try:
        create_response = template_api_env.client.post(
            "/api/v1/providers/update-jobs",
            headers=headers,
            json={
                "sources": ["kev"],
                "cve_ids": ["CVE-2024-3094"],
                "cache_only": True,
                "max_cves": 1,
            },
        )

        assert create_response.status_code == 200
        job = create_response.json()
        assert job["status"] == "completed"
        assert job["requested_sources"] == ["kev"]
        assert job["error_message"] is None
        assert job["metadata"]["snapshot_created"] is True
        assert job["metadata"]["requested_cves"] == 1
        assert job["metadata"]["provider_snapshot_id"]
        assert list(snapshot_dir.glob("provider-snapshot-*.json"))

        list_response = template_api_env.client.get(
            "/api/v1/providers/update-jobs",
            headers=headers,
        )
        assert list_response.status_code == 200
        listed = list_response.json()
        assert listed["count"] == 1
        assert listed["data"][0]["id"] == job["id"]
        assert listed["data"][0]["metadata"]["snapshot_file"] == job["metadata"]["snapshot_file"]

        status_response = template_api_env.client.get(
            "/api/v1/providers/status",
            headers=headers,
        )
        assert status_response.status_code == 200
        status_payload = status_response.json()
        assert status_payload["latest_update_job"]["id"] == job["id"]
        assert status_payload["latest_update_job"]["status"] == "completed"
        assert status_payload["snapshot_mode"] == "cache-only"
        assert status_payload["snapshot"]["selected_sources"] == ["kev"]
        assert status_payload["snapshot"]["requested_cves"] == 1
        assert status_payload["last_error"] is None
    finally:
        template_api_env.client.app.state.template_settings = active_settings


def test_template_provider_update_job_reuses_previous_provider_records(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    headers = auth_headers(template_api_env.client)
    active_settings = template_api_env.client.app.state.template_settings
    snapshot_dir = tmp_path / "template-provider-snapshots"
    cache_dir = tmp_path / "template-provider-cache"
    snapshot_dir.mkdir(parents=True)
    baseline_path = snapshot_dir / "baseline-provider-snapshot.json"
    baseline_report = ProviderSnapshotReport(
        metadata=ProviderSnapshotMetadata(
            snapshot_id="baseline-template-provider-data",
            generated_at="2026-04-30T10:00:00Z",
            input_paths=[],
            input_format="template-test",
            selected_sources=["kev"],
            requested_cves=1,
            output_path=baseline_path.name,
            cache_enabled=True,
            cache_only=True,
            cache_dir=None,
            source_hashes={"kev": "sha256:baseline-kev"},
            source_metadata={"kev": {"source": "CISA KEV catalog", "record_count": 1}},
            nvd_api_key_env="NVD_API_KEY",
        ),
        items=[
            ProviderSnapshotItem(
                cve_id="CVE-2024-3094",
                kev=KevData(
                    cve_id="CVE-2024-3094",
                    in_kev=True,
                    vulnerability_name="XZ Utils backdoor",
                    date_added="2026-04-01",
                ),
            )
        ],
    )
    baseline_document = generate_provider_snapshot_json(baseline_report)
    baseline_path.write_text(baseline_document, encoding="utf-8")
    template_api_env.client.app.state.template_settings = replace(
        active_settings,
        PROVIDER_SNAPSHOT_DIR=str(snapshot_dir),
        PROVIDER_CACHE_DIR=str(cache_dir),
    )
    try:
        with Session(template_api_env.engine) as session:
            repository = template_api_env.repositories.RunRepository(session)
            repository.create_provider_snapshot(
                kev_catalog_version="2026-04-01",
                content_hash="sha256:baseline-template-provider-data",
                source_hashes_json={"provider_snapshot": "sha256:baseline-template-provider-data"},
                source_metadata_json={
                    "snapshot_file": baseline_path.name,
                    "selected_sources": ["kev"],
                    "requested_cves": 1,
                    "generated_at": "2026-04-30T10:00:00Z",
                },
            )
            session.commit()

        response = template_api_env.client.post(
            "/api/v1/providers/update-jobs",
            headers=headers,
            json={
                "sources": ["kev"],
                "cve_ids": ["CVE-2024-3094"],
                "cache_only": True,
            },
        )

        assert response.status_code == 200
        job = response.json()
        assert job["status"] == "completed"
        assert job["metadata"]["source_counts"]["kev"]["records"] == 1
        assert job["metadata"]["source_counts"]["kev"]["fallback_from_previous_snapshot"] == 1
        generated_report = load_provider_snapshot(snapshot_dir / job["metadata"]["snapshot_file"])
        assert generated_report.items[0].kev is not None
        assert generated_report.items[0].kev.in_kev is True
        assert generated_report.items[0].kev.date_added == "2026-04-01"

        status_payload = template_api_env.client.get(
            "/api/v1/providers/status",
            headers=headers,
        ).json()
        assert status_payload["snapshot"]["kev_catalog_version"] == "2026-04-01"
        assert status_payload["sources"][2]["available"] is True
    finally:
        template_api_env.client.app.state.template_settings = active_settings


def test_template_provider_update_job_rejects_active_job(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    headers = auth_headers(template_api_env.client)
    active_settings = template_api_env.client.app.state.template_settings
    template_api_env.client.app.state.template_settings = replace(
        active_settings,
        PROVIDER_SNAPSHOT_DIR=str(tmp_path / "template-provider-snapshots"),
        PROVIDER_CACHE_DIR=str(tmp_path / "template-provider-cache"),
    )
    try:
        with Session(template_api_env.engine) as session:
            project = template_api_env.repositories.ProjectRepository(session).create_project(
                template_api_env.app_models.ProjectCreate(name="Active Provider Job"),
                owner_id=uuid.UUID("00000000-0000-4000-8000-000000000011"),
            )
            template_api_env.repositories.RunRepository(session).create_analysis_run(
                project_id=project.id,
                input_type="provider_update",
                status=template_api_env.app_models.AnalysisRunStatus.RUNNING,
                summary_json={"requested_sources": ["kev"]},
            )
            session.commit()

        response = template_api_env.client.post(
            "/api/v1/providers/update-jobs",
            headers=headers,
            json={"sources": ["kev"], "cve_ids": ["CVE-2024-3094"]},
        )

        assert response.status_code == 409
        assert "Provider update already running" in response.json()["detail"]
    finally:
        template_api_env.client.app.state.template_settings = active_settings
