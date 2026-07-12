from __future__ import annotations

import hashlib
import io
import os
import tarfile
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import create_engine
from sqlmodel import Session, select
from utils.workbench_env import create_project, seed_finding_pair
from utils.workbench_evidence_seed import _SEED_UPLOAD_CONTENT

from app import cli, repositories
from app import models as app_models
from app.cli import main
from app.core.migration_bootstrap import _alembic_config
from app.models import (
    AnalysisEvidence,
    FindingCurrentProjection,
    FindingDecisionEvidence,
    Project,
    Report,
)
from app.repositories.current_projections import FindingCurrentProjectionRepository


@pytest.fixture(autouse=True)
def _restore_process_environment() -> Iterator[None]:
    original = dict(os.environ)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


def test_vpw_database_migration_activates_only_after_full_data_parity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "source.db"
    source_url = f"sqlite:///{source}"
    config = _alembic_config()
    config.set_main_option("sqlalchemy.url", source_url)
    command.upgrade(config, "head")
    source_engine = create_engine(source_url)
    with Session(source_engine) as session:
        project = create_project(session, app_models, repositories)
        session.commit()
        project_id = project.id
    seeded = seed_finding_pair(
        source_engine,
        app_models,
        repositories,
        project_id=project_id,
        with_decision_evidence=True,
    )
    finding_ids = [uuid.UUID(str(value)) for value in seeded["finding_ids"]]
    upload_content = _SEED_UPLOAD_CONTENT
    report_content = b"verified report artifact\n"
    report_id = uuid.uuid4()
    with Session(source_engine) as session:
        analysis_evidence = session.exec(select(AnalysisEvidence)).one()
        upload = analysis_evidence.payload_json["uploads"]["input"]
        upload_ref = str(upload["storage_ref"])
        report = Report(
            id=report_id,
            project_id=project_id,
            analysis_run_id=analysis_evidence.analysis_run_id,
            kind="technical",
            format="markdown",
            filename="report.md",
            content_type="text/markdown",
            sha256=hashlib.sha256(report_content).hexdigest(),
            size_bytes=len(report_content),
            metadata_json={},
            path=(
                f"/app/workbench-reports/{project_id}/"
                f"{analysis_evidence.analysis_run_id}/{report_id}/report.md"
            ),
        )
        session.add(report)
        session.commit()
        run_id = analysis_evidence.analysis_run_id
    artifact_archive = tmp_path / "artifacts.tar"
    with tarfile.open(artifact_archive, "w") as archive:
        _add_tar_file(
            archive,
            f"workbench-import-uploads/{upload_ref}",
            upload_content,
        )
        _add_tar_file(
            archive,
            f"workbench-reports/{project_id}/{run_id}/{report_id}/report.md",
            report_content,
        )
    source_engine.dispose()
    monkeypatch.setenv("VPW_SOURCE_DATABASE_URL", source_url)
    target_dir = tmp_path / "migrated"

    assert (
        main(
            [
                "migrate",
                "database",
                "--data-dir",
                str(target_dir),
                "--artifact-archive",
                str(artifact_archive),
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert "Verified database migration completed" in output
    assert "Artifacts verified" in output
    assert source_url not in output
    target_path = target_dir / "workbench.db"
    assert target_path.is_file()
    assert not list(target_dir.glob(".workbench-migration-*"))

    target_engine = create_engine(f"sqlite:///{target_path}")
    try:
        with Session(target_engine) as session:
            assert session.exec(select(Project)).one().id == project_id
            history = list(session.exec(select(FindingDecisionEvidence)).all())
            projections = list(session.exec(select(FindingCurrentProjection)).all())
            migrated_report = session.exec(select(Report)).one()
            parity = FindingCurrentProjectionRepository(session).verify_source_parity(
                projections,
                sample_size=len(projections),
            )
        with target_engine.connect() as connection:
            journal_mode = connection.exec_driver_sql("PRAGMA journal_mode").scalar_one()
    finally:
        target_engine.dispose()

    assert {row.finding_id for row in history} == set(finding_ids)
    assert {row.finding_id for row in projections} == set(finding_ids)
    assert parity.matches is True
    assert journal_mode == "wal"
    assert Path(migrated_report.path) == (
        target_dir / "reports" / str(project_id) / str(run_id) / str(report_id) / "report.md"
    )
    assert Path(migrated_report.path).read_bytes() == report_content
    assert (target_dir / "imports" / upload_ref).read_bytes() == upload_content

    with pytest.raises(SystemExit, match="new or empty"):
        main(["migrate", "database", "--data-dir", str(target_dir)])


def test_vpw_database_migration_discards_temporary_target_on_source_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "unversioned.db"
    source_engine = create_engine(f"sqlite:///{source}")
    with source_engine.begin():
        pass
    source_engine.dispose()
    target_dir = tmp_path / "target"
    monkeypatch.setenv("VPW_SOURCE_DATABASE_URL", f"sqlite:///{source}")

    with pytest.raises(SystemExit, match="aborted without activating"):
        main(["migrate", "database", "--data-dir", str(target_dir)])

    assert not (target_dir / "workbench.db").exists()
    assert not list(target_dir.glob(".workbench-migration-*"))


def test_vpw_database_migration_hardens_temporary_database_before_activation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.db"
    source_url = f"sqlite:///{source}"
    config = _alembic_config()
    config.set_main_option("sqlalchemy.url", source_url)
    command.upgrade(config, "head")
    target_dir = tmp_path / "target"
    monkeypatch.setenv("VPW_SOURCE_DATABASE_URL", source_url)
    harden_permissions = cli._harden_permissions

    def fail_temporary_database_hardening(path: Path, mode: int) -> None:
        if path.name.startswith(".workbench-migration-"):
            raise OSError("simulated permission hardening failure")
        harden_permissions(path, mode)

    monkeypatch.setattr(cli, "_harden_permissions", fail_temporary_database_hardening)

    with pytest.raises(SystemExit, match="aborted without activating"):
        main(["migrate", "database", "--data-dir", str(target_dir)])

    assert not target_dir.exists()


def test_vpw_database_migration_cleans_target_for_invalid_source_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_dir = tmp_path / "invalid-source-target"
    monkeypatch.setenv("VPW_SOURCE_DATABASE_URL", "not-a-sqlalchemy-url")

    with pytest.raises(SystemExit, match="aborted without activating"):
        main(["migrate", "database", "--data-dir", str(target_dir)])

    assert not target_dir.exists()


def test_vpw_database_migration_rejects_unsafe_artifact_archive_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.db"
    source_url = f"sqlite:///{source}"
    config = _alembic_config()
    config.set_main_option("sqlalchemy.url", source_url)
    command.upgrade(config, "head")
    malicious_archive = tmp_path / "malicious.tar"
    with tarfile.open(malicious_archive, "w") as archive:
        _add_tar_file(archive, "../escaped.txt", b"must not escape")
    target_dir = tmp_path / "unsafe-target"
    monkeypatch.setenv("VPW_SOURCE_DATABASE_URL", source_url)

    with pytest.raises(SystemExit, match="unsafe member path"):
        main(
            [
                "migrate",
                "database",
                "--data-dir",
                str(target_dir),
                "--artifact-archive",
                str(malicious_archive),
            ]
        )

    assert not target_dir.exists()
    assert not (tmp_path / "escaped.txt").exists()


def _add_tar_file(archive: tarfile.TarFile, name: str, content: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mode = 0o600
    archive.addfile(info, io.BytesIO(content))
