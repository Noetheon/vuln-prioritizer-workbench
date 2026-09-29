from __future__ import annotations

import json
import os
import stat
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import create_engine
from sqlmodel import Session, select
from utils.workbench_env import create_project

from app import models as app_models
from app import repositories
from app.cli import main
from app.core.migration_bootstrap import _alembic_config
from app.models import Project, Report
from app.services.local_backup import (
    MANIFEST_NAME,
    BackupError,
    create_backup,
    read_manifest,
    restore_backup,
)


@pytest.fixture(autouse=True)
def _restore_process_environment() -> Iterator[None]:
    original = dict(os.environ)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


def _data_dir(root: Path) -> Path:
    root.mkdir(parents=True)
    url = f"sqlite:///{root / 'workbench.db'}"
    config = _alembic_config()
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    engine = create_engine(url)
    with Session(engine) as session:
        project = create_project(session, app_models, repositories)
        project.name = "Backed up project"
        session.add(project)
        session.commit()
    engine.dispose()
    (root / "reports" / "run-1").mkdir(parents=True)
    (root / "reports" / "run-1" / "report.md").write_text("# Report\n", encoding="utf-8")
    (root / "imports").mkdir()
    (root / "imports" / "scan.json").write_bytes(b'{"Results": []}')
    (root / "provider-cache").mkdir()
    (root / "provider-cache" / "nvd.json").write_text("{}", encoding="utf-8")
    return root


def _project_names(database: Path) -> list[str]:
    engine = create_engine(f"sqlite:///{database}")
    try:
        with Session(engine) as session:
            return list(session.exec(select(Project.name)).all())
    finally:
        engine.dispose()


def test_backup_and_restore_round_trip_through_the_cli(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _data_dir(tmp_path / "source")
    archive = tmp_path / "backups" / "vpw.zip"
    target = tmp_path / "restored"

    assert main(["backup", "--data-dir", str(source), "--output", str(archive)]) == 0
    manifest = read_manifest(archive)
    paths = [item["path"] for item in manifest["files"]]
    assert paths == ["workbench.db", "imports/scan.json", "reports/run-1/report.md"]
    assert manifest["database_revision"]
    if os.name != "nt":
        assert stat.S_IMODE(archive.stat().st_mode) == 0o600

    assert main(["restore", str(archive), "--data-dir", str(target)]) == 0
    output = capsys.readouterr().out
    assert "Backup written:" in output
    assert "Restored 3 file(s)" in output
    assert _project_names(target / "workbench.db") == ["Backed up project"]
    assert (target / "reports" / "run-1" / "report.md").read_text() == "# Report\n"
    assert not (target / "provider-cache" / "nvd.json").exists()
    assert not list(target.glob(".vpw-restore-*"))

    with pytest.raises(SystemExit, match="new or empty directory"):
        main(["restore", str(archive), "--data-dir", str(target)])
    with pytest.raises(SystemExit, match="Refusing to overwrite"):
        main(["backup", "--data-dir", str(source), "--output", str(archive)])


def test_restore_into_another_directory_moves_report_paths(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _data_dir(tmp_path / "source").resolve()
    report_file = source / "reports" / "run-1" / "report.md"
    engine = create_engine(f"sqlite:///{source / 'workbench.db'}")
    with Session(engine) as session:
        project_id = session.exec(select(Project.id)).one()
        run = repositories.RunRepository(session).create_analysis_run(
            project_id=project_id,
            input_type="cve-list",
        )
        report = Report(
            project_id=project_id,
            analysis_run_id=run.id,
            kind="technical",
            format="markdown",
            filename="report.md",
            content_type="text/markdown",
            sha256="0" * 64,
            size_bytes=report_file.stat().st_size,
            metadata_json={},
            path=str(report_file),
        )
        session.add(report)
        session.commit()
        report_id = report.id
    engine.dispose()
    archive = tmp_path / "vpw.zip"
    target = tmp_path / "moved"
    assert main(["backup", "--data-dir", str(source), "--output", str(archive)]) == 0
    assert read_manifest(archive)["data_root"] == str(source)

    assert main(["restore", str(archive), "--data-dir", str(target)]) == 0

    assert "Updated 1 report path(s)" in capsys.readouterr().out
    engine = create_engine(f"sqlite:///{target / 'workbench.db'}")
    try:
        with Session(engine) as session:
            restored = session.get(Report, report_id)
            assert restored is not None
            restored_path = Path(restored.path)
    finally:
        engine.dispose()
    assert restored_path == target.resolve() / "reports" / "run-1" / "report.md"
    assert restored_path.read_text() == "# Report\n"


def test_backup_can_include_the_provider_cache(tmp_path: Path) -> None:
    source = _data_dir(tmp_path / "source")

    result = create_backup(
        source,
        tmp_path / "with-cache.zip",
        package_version="test",
        include_cache=True,
    )

    assert result.files == 4
    assert "provider-cache/nvd.json" in [
        item["path"] for item in read_manifest(result.path)["files"]
    ]


def _rewrite(archive: Path, target: Path, *, entries: dict[str, bytes], manifest: dict) -> None:
    with zipfile.ZipFile(target, "w") as bundle:
        for name, content in entries.items():
            bundle.writestr(name, content)
        bundle.writestr(MANIFEST_NAME, json.dumps(manifest))


def test_restore_rejects_damaged_or_unsafe_archives_without_leaving_files(
    tmp_path: Path,
) -> None:
    source = _data_dir(tmp_path / "source")
    archive = tmp_path / "vpw.zip"
    create_backup(source, archive, package_version="test")
    manifest = read_manifest(archive)
    with zipfile.ZipFile(archive) as bundle:
        entries = {name: bundle.read(name) for name in bundle.namelist() if name != MANIFEST_NAME}

    tampered = tmp_path / "tampered.zip"
    _rewrite(
        archive,
        tampered,
        entries={**entries, "reports/run-1/report.md": b"# Rep0rt\n"},
        manifest=manifest,
    )
    with pytest.raises(BackupError, match="Checksum mismatch"):
        restore_backup(tampered, tmp_path / "tampered-target")
    assert not (tmp_path / "tampered-target").exists()

    escaping = tmp_path / "escaping.zip"
    _rewrite(
        archive,
        escaping,
        entries={**entries, "reports/../../evil.txt": b"x"},
        manifest={
            **manifest,
            "files": [
                *manifest["files"],
                {"path": "reports/../../evil.txt", "sha256": "0" * 64, "size": 1},
            ],
        },
    )
    with pytest.raises(BackupError, match="Unsafe or duplicate path"):
        restore_backup(escaping, tmp_path / "escaping-target")
    assert not (tmp_path / "escaping-target").exists()
    assert not (tmp_path / "evil.txt").exists()

    unlisted = tmp_path / "unlisted.zip"
    _rewrite(archive, unlisted, entries={**entries, "imports/extra.json": b"{}"}, manifest=manifest)
    with pytest.raises(BackupError, match="do not match the manifest"):
        restore_backup(unlisted, tmp_path / "unlisted-target")

    foreign = tmp_path / "foreign.zip"
    _rewrite(archive, foreign, entries=entries, manifest={**manifest, "format": "other"})
    with pytest.raises(BackupError, match="Unsupported backup format"):
        read_manifest(foreign)


def test_restore_refuses_backups_from_a_newer_schema(tmp_path: Path) -> None:
    source = _data_dir(tmp_path / "source")
    archive = tmp_path / "vpw.zip"
    create_backup(source, archive, package_version="test")
    manifest = read_manifest(archive)
    with zipfile.ZipFile(archive) as bundle:
        entries = {name: bundle.read(name) for name in bundle.namelist() if name != MANIFEST_NAME}
    newer = tmp_path / "newer.zip"
    _rewrite(archive, newer, entries=entries, manifest={**manifest, "database_revision": "9999"})

    with pytest.raises(SystemExit, match="newer VPW version"):
        main(["restore", str(newer), "--data-dir", str(tmp_path / "target")])
    assert not (tmp_path / "target").exists()


def test_backup_requires_an_existing_database(tmp_path: Path) -> None:
    missing = str(tmp_path / "missing")
    with pytest.raises(SystemExit, match="No Workbench database"):
        main(["backup", "--data-dir", missing, "--output", str(tmp_path / "a.zip")])
