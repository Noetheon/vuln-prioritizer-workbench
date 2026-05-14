from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlmodel import Session
from utils.workbench_env import WorkbenchApiEnv, local_api_headers

from app.models.base import get_datetime_utc
from app.services import provider_updates as provider_updates_module
from app.services.provider_status import provider_status_payload
from app.services.provider_updates import (
    PROVIDER_UPDATE_LOCK_FILE,
    reconcile_stale_provider_update_runs,
)
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


def test_workbench_provider_status_is_available_locally(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    response = workbench_api_env.client.get("/api/v1/providers/status")

    assert response.status_code == 200
    assert response.json()["snapshot_mode"] == "missing"


def test_workbench_provider_status_reports_missing_snapshot(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)

    response = workbench_api_env.client.get("/api/v1/providers/status", headers=headers)

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


def test_workbench_provider_status_reports_latest_snapshot(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    snapshot_id = uuid.uuid4()
    created_at = datetime(2026, 4, 28, 10, 0, tzinfo=UTC)
    with Session(workbench_api_env.engine) as session:
        session.add(
            workbench_api_env.app_models.ProviderSnapshot(
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

    response = workbench_api_env.client.get("/api/v1/providers/status", headers=headers)

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


def test_workbench_provider_status_does_not_treat_null_source_hash_as_available(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    with Session(workbench_api_env.engine) as session:
        session.add(
            workbench_api_env.app_models.ProviderSnapshot(
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

    response = workbench_api_env.client.get("/api/v1/providers/status", headers=headers)

    assert response.status_code == 200
    sources = {source["name"]: source for source in response.json()["sources"]}
    assert sources["nvd"]["available"] is False
    assert sources["epss"]["available"] is False
    assert sources["kev"]["available"] is False
    assert sources["attack_stix"]["available"] is False


def test_workbench_provider_status_surfaces_failed_provider_update(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    with Session(workbench_api_env.engine) as session:
        repository = workbench_api_env.repositories.RunRepository(session)
        snapshot = repository.create_provider_snapshot(
            nvd_last_sync="2026-04-28T10:15:00Z",
            epss_date="2026-04-28",
            kev_catalog_version="2026-04-28",
            content_hash="sha256:provider-status-error-fixture",
            source_metadata_json={"selected_sources": ["nvd", "epss", "kev"]},
        )
        project = workbench_api_env.repositories.ProjectRepository(session).create_project(
            workbench_api_env.app_models.ProjectCreate(name="Provider Status Project")
        )
        repository.create_analysis_run(
            project_id=project.id,
            input_type="provider_update",
            status=workbench_api_env.app_models.AnalysisRunStatus.FAILED,
            provider_snapshot_id=snapshot.id,
            summary_json={"requested_sources": ["nvd", "epss", "kev"]},
            error_json={"detail": "forced provider cache failure"},
        )
        session.commit()

    response = workbench_api_env.client.get("/api/v1/providers/status", headers=headers)

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


def test_workbench_provider_status_redacts_production_paths_and_cache_details(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    active_settings = workbench_api_env.client.app.state.workbench_settings
    private_snapshot = tmp_path / "private" / "provider-snapshot.json"
    private_cache = tmp_path / "private" / "cache"
    with Session(workbench_api_env.engine) as session:
        session.add(
            workbench_api_env.app_models.ProviderSnapshot(
                id=uuid.uuid4(),
                created_at=datetime(2026, 4, 28, 10, 0, tzinfo=UTC),
                content_hash="sha256:provider-production-redaction",
                nvd_last_sync="2026-04-28T10:15:00Z",
                source_hashes_json={"nvd": "sha256:nvd-cache-namespace"},
                source_metadata_json={
                    "selected_sources": ["nvd"],
                    "generated_at": "2026-04-28T10:30:00Z",
                    "cache_dir": str(private_cache),
                    "snapshot_dir": str(private_snapshot.parent),
                    "source_path": str(private_snapshot),
                    "warnings": [f"using cache from {private_cache}"],
                    "source_metadata": {
                        "nvd": {
                            "source": "NVD CVE API 2.0",
                            "record_count": 1,
                            "cache_namespace_hash": "sha256:nvd-cache-namespace",
                        }
                    },
                },
            )
        )
        session.commit()

    workbench_api_env.client.app.state.workbench_settings = replace(
        active_settings,
        ENVIRONMENT="production",
        SECRET_KEY="workbench-shell-secret-0123456789abcdef",
        FRONTEND_HOST="https://workbench.example.com",
        ALLOWED_HOSTS=("workbench.example.com",),
        PROVIDER_CACHE_DIR=str(private_cache),
        PROVIDER_SNAPSHOT_DIR=str(private_snapshot.parent),
    )
    try:
        response = workbench_api_env.client.get("/api/v1/providers/status")
    finally:
        workbench_api_env.client.app.state.workbench_settings = active_settings

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["cache_dir"] is None
    assert payload["snapshot_dir"] is None
    assert payload["snapshot"]["source_path"] is None
    assert payload["snapshot"]["source_hashes"] == {}
    assert "cache_dir" not in payload["snapshot"]["source_metadata"]
    assert "snapshot_dir" not in payload["snapshot"]["source_metadata"]
    assert "source_path" not in payload["snapshot"]["source_metadata"]
    assert payload["snapshot"]["source_metadata"]["source_metadata"]["nvd"] == {
        "source": "NVD CVE API 2.0",
        "record_count": 1,
    }
    assert str(tmp_path) not in response.text
    assert "cache_namespace_hash" not in response.text


def test_provider_status_projection_uses_source_hashes_when_metadata_omits_selection(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    active_settings = workbench_api_env.client.app.state.workbench_settings
    snapshot = workbench_api_env.app_models.ProviderSnapshot(
        id=uuid.UUID("00000000-0000-4000-8000-000000000201"),
        created_at=datetime(2026, 4, 28, 10, 0),
        content_hash="sha256:provider-source-hash-fallback",
        source_hashes_json={"kev": "sha256:kev-cache", "custom_feed": "sha256:custom"},
        source_metadata_json={
            "requested_cves": "7",
            "cache_only": "true",
            "output_path": "provider-snapshot.json",
        },
    )

    payload = provider_status_payload(
        snapshot,
        latest_update_run=None,
        active_settings=active_settings,
    )

    assert payload.snapshot.selected_sources == ["kev", "custom_feed"]
    assert payload.snapshot.requested_cves == 7
    assert payload.snapshot.mode == "cache-only"
    assert payload.snapshot.source_path == "provider-snapshot.json"
    sources = {source.name: source for source in payload.sources}
    assert sources["kev"].selected is True
    assert sources["kev"].available is True
    assert sources["custom_feed"].selected is True
    assert sources["custom_feed"].available is True
    assert sources["custom_feed"].detail == "custom_feed status from the latest stored snapshot."
    assert isinstance(payload.cache_age_seconds, int)


def test_provider_status_projection_falls_back_to_available_snapshot_columns(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    active_settings = workbench_api_env.client.app.state.workbench_settings
    snapshot = workbench_api_env.app_models.ProviderSnapshot(
        id=uuid.UUID("00000000-0000-4000-8000-000000000202"),
        created_at=datetime(2026, 4, 28, 10, 0, tzinfo=UTC),
        content_hash="sha256:provider-column-fallback",
        nvd_last_sync="2026-04-28T10:15:00Z",
        epss_date="2026-04-28",
        source_metadata_json={"locked_provider_data": "yes"},
    )

    payload = provider_status_payload(
        snapshot,
        latest_update_run=None,
        active_settings=active_settings,
    )

    assert payload.snapshot.selected_sources == ["nvd", "epss"]
    assert payload.snapshot.mode == "locked"
    sources = {source.name: source for source in payload.sources}
    assert sources["nvd"].selected is True
    assert sources["nvd"].last_sync == "2026-04-28T10:15:00Z"
    assert sources["epss"].selected is True
    assert sources["epss"].last_sync == "2026-04-28"
    assert sources["kev"].selected is False
    assert sources["kev"].available is False


def test_provider_status_projection_redacts_failed_job_error_json_fallback(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    active_settings = workbench_api_env.client.app.state.workbench_settings
    private_path = tmp_path / "private-cache" / "provider.json"
    failed_run = workbench_api_env.app_models.AnalysisRun(
        id=uuid.UUID("00000000-0000-4000-8000-000000000203"),
        project_id=uuid.UUID("00000000-0000-4000-8000-000000000204"),
        input_type="provider_update",
        status=workbench_api_env.app_models.AnalysisRunStatus.FAILED,
        error_json={"nested": {"path": str(private_path)}, "fallback": str(private_path)},
        summary_json={
            "sources": ["nvd"],
            "execution_mode": "scheduled",
            "provider_cache_dir": str(private_path.parent),
        },
        started_at=datetime(2026, 4, 28, 10, 0, tzinfo=UTC),
    )

    payload = provider_status_payload(
        None,
        latest_update_run=failed_run,
        active_settings=replace(
            active_settings,
            ENVIRONMENT="production",
            SECRET_KEY="workbench-shell-secret-0123456789abcdef",
            FRONTEND_HOST="https://workbench.example.com",
            ALLOWED_HOSTS=("workbench.example.com",),
        ),
    )

    assert payload.status == "degraded"
    assert payload.cache_dir is None
    assert payload.snapshot_dir is None
    assert payload.latest_update_job is not None
    assert payload.latest_update_job.execution_mode == "scheduled"
    assert payload.latest_update_job.requested_sources == ["nvd"]
    assert "provider_cache_dir" not in payload.latest_update_job.metadata_
    assert payload.last_error is not None
    assert str(tmp_path) not in payload.last_error
    assert all(str(tmp_path) not in warning for warning in payload.warnings)


def test_workbench_provider_update_job_create_list_and_status(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    active_settings = workbench_api_env.client.app.state.workbench_settings
    snapshot_dir = tmp_path / "workbench-provider-snapshots"
    cache_dir = tmp_path / "workbench-provider-cache"
    workbench_api_env.client.app.state.workbench_settings = replace(
        active_settings,
        PROVIDER_SNAPSHOT_DIR=str(snapshot_dir),
        PROVIDER_CACHE_DIR=str(cache_dir),
    )
    try:
        create_response = workbench_api_env.client.post(
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
        assert job["execution_mode"] == "request"
        assert job["requested_sources"] == ["kev"]
        assert job["error_message"] is None
        assert job["metadata"]["execution_mode"] == "request"
        assert job["metadata"]["snapshot_created"] is True
        assert job["metadata"]["requested_cves"] == 1
        assert job["metadata"]["provider_snapshot_id"]
        snapshot_files = list(snapshot_dir.glob("provider-snapshot-*.json"))
        assert snapshot_files
        snapshot_report = load_provider_snapshot(snapshot_files[0])
        assert snapshot_report.metadata.snapshot_format == "provider-snapshot.v1.json"
        assert snapshot_report.metadata.cache_only is True
        assert snapshot_report.metadata.selected_sources == ["kev"]
        assert snapshot_report.metadata.input_format == "workbench-current-findings"

        list_response = workbench_api_env.client.get(
            "/api/v1/providers/update-jobs",
            headers=headers,
        )
        assert list_response.status_code == 200
        listed = list_response.json()
        assert listed["count"] == 1
        assert listed["data"][0]["id"] == job["id"]
        assert listed["data"][0]["metadata"]["snapshot_file"] == job["metadata"]["snapshot_file"]

        status_response = workbench_api_env.client.get(
            "/api/v1/providers/status",
            headers=headers,
        )
        assert status_response.status_code == 200
        status_payload = status_response.json()
        assert status_payload["latest_update_job"]["id"] == job["id"]
        assert status_payload["latest_update_job"]["status"] == "completed"
        assert status_payload["latest_update_job"]["execution_mode"] == "request"
        assert status_payload["snapshot_mode"] == "cache-only"
        assert status_payload["snapshot"]["selected_sources"] == ["kev"]
        assert status_payload["snapshot"]["requested_cves"] == 1
        assert status_payload["snapshot"]["source_metadata"]["snapshot_format"] == (
            "provider-snapshot.v1.json"
        )
        assert status_payload["snapshot"]["source_metadata"]["input_format"] == (
            "workbench-current-findings"
        )
        assert status_payload["last_error"] is None
    finally:
        workbench_api_env.client.app.state.workbench_settings = active_settings


def test_workbench_provider_update_job_can_run_in_background(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    active_settings = workbench_api_env.client.app.state.workbench_settings
    workbench_api_env.client.app.state.workbench_settings = replace(
        active_settings,
        PROVIDER_SNAPSHOT_DIR=str(tmp_path / "workbench-provider-snapshots"),
        PROVIDER_CACHE_DIR=str(tmp_path / "workbench-provider-cache"),
    )
    try:
        response = workbench_api_env.client.post(
            "/api/v1/providers/update-jobs",
            headers=headers,
            json={
                "sources": ["kev"],
                "cve_ids": ["CVE-2024-3094"],
                "cache_only": True,
                "execution_mode": "background",
            },
        )

        assert response.status_code == 200, response.text
        queued_job = response.json()
        assert queued_job["execution_mode"] == "background"
        assert queued_job["status"] == "pending"

        with Session(workbench_api_env.engine) as session:
            run = session.get(
                workbench_api_env.app_models.AnalysisRun,
                uuid.UUID(queued_job["id"]),
            )

        assert run is not None
        assert run.status == workbench_api_env.app_models.AnalysisRunStatus.COMPLETED
        assert run.summary_json["execution_mode"] == "background"
        assert run.summary_json["snapshot_created"] is True
    finally:
        workbench_api_env.client.app.state.workbench_settings = active_settings


def test_workbench_provider_update_live_failure_preserves_previous_snapshot(
    monkeypatch,
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    class FailingKevProvider:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def fetch_many(
            self,
            cve_ids: list[str],
            *,
            refresh: bool = False,
        ) -> tuple[dict[str, KevData], list[str]]:
            assert refresh is True
            return (
                {cve_id: KevData(cve_id=cve_id, in_kev=False) for cve_id in cve_ids},
                ["KEV catalog load failed: upstream unavailable"],
            )

    headers = local_api_headers(workbench_api_env.client)
    active_settings = workbench_api_env.client.app.state.workbench_settings
    snapshot_dir = tmp_path / "workbench-provider-snapshots"
    cache_dir = tmp_path / "workbench-provider-cache"
    workbench_api_env.client.app.state.workbench_settings = replace(
        active_settings,
        PROVIDER_SNAPSHOT_DIR=str(snapshot_dir),
        PROVIDER_CACHE_DIR=str(cache_dir),
    )
    monkeypatch.setattr(provider_updates_module, "KevProvider", FailingKevProvider)
    try:
        snapshot_dir.mkdir()
        baseline_path = snapshot_dir / "baseline-provider-snapshot.json"
        baseline_path.write_text(
            generate_provider_snapshot_json(
                ProviderSnapshotReport(
                    metadata=ProviderSnapshotMetadata(
                        snapshot_id="baseline-workbench-provider-data",
                        generated_at="2026-04-30T10:00:00Z",
                        input_paths=[],
                        input_format="workbench-test",
                        selected_sources=["kev"],
                        requested_cves=1,
                        output_path=baseline_path.name,
                        cache_enabled=True,
                        cache_only=True,
                        cache_dir=None,
                        source_hashes={"kev": "sha256:baseline-kev"},
                        source_metadata={"kev": {"source": "CISA KEV catalog"}},
                        nvd_api_key_env=None,
                    ),
                    items=[ProviderSnapshotItem(cve_id="CVE-2024-3094")],
                )
            ),
            encoding="utf-8",
        )
        with Session(workbench_api_env.engine) as session:
            previous_snapshot = workbench_api_env.repositories.RunRepository(
                session
            ).create_provider_snapshot(
                kev_catalog_version="2026-04-01",
                content_hash="sha256:baseline-workbench-provider-data",
                source_hashes_json={"provider_snapshot": "sha256:baseline-workbench-provider-data"},
                source_metadata_json={
                    "snapshot_file": baseline_path.name,
                    "selected_sources": ["kev"],
                    "requested_cves": 1,
                    "generated_at": "2026-04-30T10:00:00Z",
                },
            )
            previous_snapshot_id = previous_snapshot.id
            session.commit()

        response = workbench_api_env.client.post(
            "/api/v1/providers/update-jobs",
            headers=headers,
            json={
                "sources": ["kev"],
                "cve_ids": ["CVE-2024-3094"],
                "cache_only": False,
            },
        )

        assert response.status_code == 200, response.text
        job = response.json()
        assert job["status"] == "failed"
        assert job["metadata"]["snapshot_created"] is False
        assert "upstream unavailable" in job["error_message"]
        assert sorted(path.name for path in snapshot_dir.glob("*.json")) == [
            "baseline-provider-snapshot.json"
        ]

        status_payload = workbench_api_env.client.get(
            "/api/v1/providers/status",
            headers=headers,
        ).json()
        assert status_payload["status"] == "degraded"
        assert status_payload["snapshot"]["id"] == str(previous_snapshot_id)
        assert status_payload["latest_update_job"]["id"] == job["id"]
        assert any("Latest provider update failed" in item for item in status_payload["warnings"])
    finally:
        workbench_api_env.client.app.state.workbench_settings = active_settings


def test_workbench_provider_update_job_reuses_previous_provider_records(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    active_settings = workbench_api_env.client.app.state.workbench_settings
    snapshot_dir = tmp_path / "workbench-provider-snapshots"
    cache_dir = tmp_path / "workbench-provider-cache"
    snapshot_dir.mkdir(parents=True)
    baseline_path = snapshot_dir / "baseline-provider-snapshot.json"
    baseline_report = ProviderSnapshotReport(
        metadata=ProviderSnapshotMetadata(
            snapshot_id="baseline-workbench-provider-data",
            generated_at="2026-04-30T10:00:00Z",
            input_paths=[],
            input_format="workbench-test",
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
    workbench_api_env.client.app.state.workbench_settings = replace(
        active_settings,
        PROVIDER_SNAPSHOT_DIR=str(snapshot_dir),
        PROVIDER_CACHE_DIR=str(cache_dir),
    )
    try:
        with Session(workbench_api_env.engine) as session:
            repository = workbench_api_env.repositories.RunRepository(session)
            repository.create_provider_snapshot(
                kev_catalog_version="2026-04-01",
                content_hash="sha256:baseline-workbench-provider-data",
                source_hashes_json={"provider_snapshot": "sha256:baseline-workbench-provider-data"},
                source_metadata_json={
                    "snapshot_file": baseline_path.name,
                    "selected_sources": ["kev"],
                    "requested_cves": 1,
                    "generated_at": "2026-04-30T10:00:00Z",
                },
            )
            session.commit()

        response = workbench_api_env.client.post(
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

        status_payload = workbench_api_env.client.get(
            "/api/v1/providers/status",
            headers=headers,
        ).json()
        assert status_payload["snapshot"]["kev_catalog_version"] == "2026-04-01"
        assert status_payload["sources"][2]["available"] is True
    finally:
        workbench_api_env.client.app.state.workbench_settings = active_settings


def test_workbench_provider_update_job_audits_failed_synchronous_run(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    active_settings = workbench_api_env.client.app.state.workbench_settings
    snapshot_file = tmp_path / "provider-snapshots-as-file"
    snapshot_file.write_text("not a directory", encoding="utf-8")
    workbench_api_env.client.app.state.workbench_settings = replace(
        active_settings,
        PROVIDER_SNAPSHOT_DIR=str(snapshot_file),
        PROVIDER_CACHE_DIR=str(tmp_path / "workbench-provider-cache"),
    )
    try:
        response = workbench_api_env.client.post(
            "/api/v1/providers/update-jobs",
            headers=headers,
            json={
                "sources": ["kev"],
                "cve_ids": ["CVE-2024-3094"],
                "cache_only": True,
            },
        )

        assert response.status_code == 200, response.text
        job = response.json()
        assert job["status"] == "failed"
        assert job["error_message"]

        audit_response = workbench_api_env.client.get("/api/v1/audit/events", headers=headers)
        assert audit_response.status_code == 200, audit_response.text
        audit_event = next(
            item
            for item in audit_response.json()["data"]
            if item["action"] == "provider.update_job.create"
        )
        assert audit_event["status"] == "failure"
        assert audit_event["resource_id"] == job["id"]
        assert audit_event["detail"]["status"] == "failed"
    finally:
        workbench_api_env.client.app.state.workbench_settings = active_settings


def test_workbench_provider_update_job_rejects_active_job(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    active_settings = workbench_api_env.client.app.state.workbench_settings
    workbench_api_env.client.app.state.workbench_settings = replace(
        active_settings,
        PROVIDER_SNAPSHOT_DIR=str(tmp_path / "workbench-provider-snapshots"),
        PROVIDER_CACHE_DIR=str(tmp_path / "workbench-provider-cache"),
    )
    try:
        with Session(workbench_api_env.engine) as session:
            project = workbench_api_env.repositories.ProjectRepository(session).create_project(
                workbench_api_env.app_models.ProjectCreate(name="Active Provider Job")
            )
            workbench_api_env.repositories.RunRepository(session).create_analysis_run(
                project_id=project.id,
                input_type="provider_update",
                status=workbench_api_env.app_models.AnalysisRunStatus.RUNNING,
                summary_json={"requested_sources": ["kev"]},
            )
            session.commit()

        response = workbench_api_env.client.post(
            "/api/v1/providers/update-jobs",
            headers=headers,
            json={"sources": ["kev"], "cve_ids": ["CVE-2024-3094"]},
        )

        assert response.status_code == 409
        assert response.json()["code"] == "conflict"
        assert "Provider update already running" in response.json()["detail"]
    finally:
        workbench_api_env.client.app.state.workbench_settings = active_settings


def test_workbench_provider_update_reconciliation_fails_stale_active_job(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    active_settings = replace(
        workbench_api_env.client.app.state.workbench_settings,
        PROVIDER_SNAPSHOT_DIR=str(tmp_path / "workbench-provider-snapshots"),
        PROVIDER_CACHE_DIR=str(tmp_path / "workbench-provider-cache"),
        PROVIDER_UPDATE_STALE_MINUTES=1,
    )
    with Session(workbench_api_env.engine) as session:
        project = workbench_api_env.repositories.ProjectRepository(session).create_project(
            workbench_api_env.app_models.ProjectCreate(name="Stale Provider Job")
        )
        run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project.id,
            input_type="provider_update",
            status=workbench_api_env.app_models.AnalysisRunStatus.RUNNING,
            summary_json={
                "requested_sources": ["kev"],
                "requested_cves": 1,
                "cache_only": True,
                "execution_mode": "request",
            },
        )
        run.started_at = get_datetime_utc() - timedelta(minutes=5)
        session.add(run)
        session.commit()
        run_id = run.id

    reconciled = reconcile_stale_provider_update_runs(
        engine=workbench_api_env.engine,
        settings=active_settings,
    )

    assert reconciled == 1
    with Session(workbench_api_env.engine) as session:
        reconciled_run = session.get(workbench_api_env.app_models.AnalysisRun, run_id)

    assert reconciled_run is not None
    assert reconciled_run.status == workbench_api_env.app_models.AnalysisRunStatus.FAILED
    assert reconciled_run.finished_at is not None
    assert "did not finish" in reconciled_run.error_message


def test_workbench_provider_update_job_rejects_active_filesystem_lock(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    active_settings = workbench_api_env.client.app.state.workbench_settings
    snapshot_dir = tmp_path / "workbench-provider-snapshots"
    snapshot_dir.mkdir()
    (snapshot_dir / PROVIDER_UPDATE_LOCK_FILE).write_text("active", encoding="utf-8")
    workbench_api_env.client.app.state.workbench_settings = replace(
        active_settings,
        PROVIDER_SNAPSHOT_DIR=str(snapshot_dir),
        PROVIDER_CACHE_DIR=str(tmp_path / "workbench-provider-cache"),
    )
    try:
        response = workbench_api_env.client.post(
            "/api/v1/providers/update-jobs",
            headers=headers,
            json={"sources": ["kev"], "cve_ids": ["CVE-2024-3094"]},
        )

        assert response.status_code == 409
        assert response.json()["code"] == "conflict"
        assert "Provider update already running" in response.json()["detail"]
        with Session(workbench_api_env.engine) as session:
            update_runs = workbench_api_env.repositories.RunRepository(
                session
            ).list_provider_update_runs()
        assert update_runs == []
    finally:
        workbench_api_env.client.app.state.workbench_settings = active_settings
