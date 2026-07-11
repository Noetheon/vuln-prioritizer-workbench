"""Command-line entrypoint for the local single-process Workbench."""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import threading
import time
import urllib.error
import urllib.request
import uuid
import webbrowser
from collections.abc import Sequence
from importlib import metadata, resources
from pathlib import Path
from typing import Any


def main(argv: Sequence[str] | None = None) -> int:
    """Run the packaged Workbench command line."""
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "serve":
        return _serve(args)
    if args.command == "ledger":
        return _ledger(args)
    if args.command == "migrate":
        return _migrate(args)
    parser.print_help()
    return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vpw",
        description="Vuln Prioritizer Workbench local runtime.",
    )
    parser.add_argument("--version", action="version", version=_package_version())
    commands = parser.add_subparsers(dest="command")

    serve = commands.add_parser("serve", help="Start the local browser Workbench.")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--data-dir", type=Path, default=None)
    serve.add_argument("--no-browser", action="store_true")
    serve.add_argument("--allow-network", action="store_true")
    serve.add_argument("--log-level", default="info", choices=("debug", "info", "warning", "error"))

    ledger = commands.add_parser("ledger", help="Maintain or verify the Decision Ledger.")
    ledger.add_argument("action", choices=("backfill", "verify"))
    ledger.add_argument("--data-dir", type=Path, default=None)
    ledger.add_argument("--strict", action="store_true")

    migrate = commands.add_parser(
        "migrate",
        help="Copy a same-version database into a verified local SQLite instance.",
    )
    migrate.add_argument("action", choices=("database",))
    migrate.add_argument("--data-dir", type=Path, required=True)
    migrate.add_argument("--source-url-env", default="VPW_SOURCE_DATABASE_URL")
    migrate.add_argument("--source-postgres-env", action="store_true")
    migrate.add_argument("--artifact-archive", type=Path, default=None)
    return parser


def _serve(args: argparse.Namespace) -> int:
    host = str(args.host).strip()
    _validate_bind(host=host, port=args.port, allow_network=bool(args.allow_network))
    data_dir = _prepare_runtime_environment(
        data_dir=args.data_dir,
        host=host,
        port=args.port,
        in_process_worker=True,
    )
    active_settings = _migrate_and_load_settings()
    _harden_permissions(data_dir / "workbench.db", 0o600)

    from app.main import create_app

    application = create_app(active_settings)
    if not bool(getattr(application.state, "frontend_mounted", False)):
        raise SystemExit(
            "Packaged frontend assets are missing. Reinstall the release wheel or run "
            "the frontend runtime asset build."
        )
    url = f"http://{host}:{args.port}"
    print(f"VPW data: {data_dir}")
    print(f"Workbench: {url}")
    if not args.no_browser:
        threading.Thread(
            target=_open_browser_when_ready,
            args=(url,),
            name="vpw-browser-opener",
            daemon=True,
        ).start()

    import uvicorn

    uvicorn.run(
        application,
        host=host,
        port=args.port,
        log_level=args.log_level,
        access_log=args.log_level == "debug",
    )
    return 0


def _ledger(args: argparse.Namespace) -> int:
    _prepare_runtime_environment(
        data_dir=args.data_dir,
        host="127.0.0.1",
        port=8765,
        in_process_worker=False,
    )
    active_settings = _migrate_and_load_settings()
    runtime_root = (args.data_dir or _default_data_dir()).expanduser().resolve(strict=False)
    _harden_permissions(runtime_root / "workbench.db", 0o600)

    from sqlmodel import Session

    from app.core.db import create_db_engine
    from app.repositories.current_projections import FindingCurrentProjectionRepository

    engine = create_db_engine(active_settings)
    try:
        with Session(engine) as session:
            repository = FindingCurrentProjectionRepository(session)
            if args.action == "backfill":
                inserted = repository.backfill_missing()
                session.commit()
                print(f"Decision Ledger backfill inserted {inserted} current projection row(s).")
                return 0
            result = repository.verify_all_source_parity()
            print(
                f"Decision Ledger parity checked {result.checked} projection row(s); "
                f"mismatches={len(result.mismatches)}."
            )
            if result.mismatches:
                for mismatch in result.mismatches:
                    print(f"- {mismatch}")
                return 1 if args.strict else 0
            return 0
    finally:
        engine.dispose()


def _migrate(args: argparse.Namespace) -> int:
    if args.action != "database":  # pragma: no cover - guarded by argparse
        raise SystemExit(f"Unsupported migration action: {args.action}")
    source_url = _migration_source_url(args)
    requested_root = args.data_dir.expanduser().resolve(strict=False)
    target_root_preexisted = requested_root.exists()
    if requested_root.exists() and any(requested_root.iterdir()):
        raise SystemExit(f"Migration target must be a new or empty directory: {requested_root}.")

    root = _prepare_runtime_environment(
        data_dir=args.data_dir,
        host="127.0.0.1",
        port=8765,
        in_process_worker=False,
    )
    target = root / "workbench.db"
    temporary = root / f".workbench-migration-{uuid.uuid4().hex}.db"
    artifact_staging = root / f".artifact-migration-{uuid.uuid4().hex}"
    os.environ["SQLALCHEMY_DATABASE_URI"] = _sqlite_uri(temporary)

    from sqlalchemy import create_engine
    from sqlalchemy.exc import SQLAlchemyError

    from app.core.db import create_db_engine
    from app.domain.engine.security_redaction import redact_error
    from app.services.artifact_migration import (
        ArtifactMigrationInvariantError,
        activate_staged_artifacts,
        required_artifact_references,
        stage_and_verify_compose_artifacts,
    )
    from app.services.database_migration import (
        DatabaseMigrationInvariantError,
        copy_database_with_parity,
    )

    source_engine = None
    target_engine = None
    artifact_result = None
    try:
        source_engine = create_engine(source_url, pool_pre_ping=True)
        active_settings = _migrate_and_load_settings()
        target_engine = create_db_engine(active_settings)
        result = copy_database_with_parity(
            source_engine,
            target_engine,
            target_report_root=root / "reports",
        )
        required_artifacts = required_artifact_references(target_engine)
        if args.artifact_archive is None and required_artifacts:
            raise ArtifactMigrationInvariantError(
                f"The database references {required_artifacts} managed artifact(s); "
                "provide --artifact-archive from scripts/workbench-backup.sh."
            )
        if args.artifact_archive is not None:
            artifact_result = stage_and_verify_compose_artifacts(
                args.artifact_archive,
                artifact_staging,
                target_engine=target_engine,
                final_data_root=root,
            )
        with target_engine.begin() as connection:
            connection.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
        target_engine.dispose()
        target_engine = None
        _harden_permissions(temporary, 0o600)
        if artifact_result is not None:
            activate_staged_artifacts(artifact_staging, root)
            _ensure_packaged_demo_snapshot(root / "provider-snapshots")
        temporary.replace(target)
        _remove_sqlite_files(temporary)
    except (
        ArtifactMigrationInvariantError,
        DatabaseMigrationInvariantError,
        OSError,
        SQLAlchemyError,
        ValueError,
    ) as exc:
        safe_error = redact_error(exc, extra_secrets=(source_url,))
        raise SystemExit(
            f"Database migration aborted without activating a target: {safe_error}"
        ) from exc
    finally:
        if target_engine is not None:
            target_engine.dispose()
        if source_engine is not None:
            source_engine.dispose()
        if not target.exists():
            _remove_sqlite_files(temporary)
            shutil.rmtree(artifact_staging, ignore_errors=True)
            for name in ("imports", "reports", "provider-snapshots", "provider-cache"):
                shutil.rmtree(root / name, ignore_errors=True)
            if not target_root_preexisted:
                shutil.rmtree(root, ignore_errors=True)

    print(
        f"Verified database migration completed at revision {result.revision}: "
        f"{len(result.tables)} tables, {result.total_rows} rows."
    )
    if artifact_result is not None:
        print(
            f"Artifacts verified: files={artifact_result.files}, "
            f"bytes={artifact_result.bytes}, reports={artifact_result.verified_reports}, "
            f"uploads={artifact_result.verified_uploads}."
        )
    print(f"Target: {target}")
    return 0


def _prepare_runtime_environment(
    *,
    data_dir: Path | None,
    host: str,
    port: int,
    in_process_worker: bool,
) -> Path:
    root = (data_dir or _default_data_dir()).expanduser().resolve(strict=False)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    _harden_permissions(root, 0o700)
    upload_dir = root / "imports"
    report_dir = root / "reports"
    cache_dir = root / "provider-cache"
    snapshot_dir = root / "provider-snapshots"
    for path in (upload_dir, report_dir, cache_dir, snapshot_dir):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        _harden_permissions(path, 0o700)

    resource_root = Path(str(resources.files("app").joinpath("resources")))
    _ensure_packaged_demo_snapshot(snapshot_dir, resource_root=resource_root)
    database_uri = _sqlite_uri(root / "workbench.db")
    environment = {
        "ENVIRONMENT": "local",
        "SQLALCHEMY_DATABASE_URI": database_uri,
        "IMPORT_UPLOAD_DIR": str(upload_dir),
        "REPORT_DIR": str(report_dir),
        "PROVIDER_CACHE_DIR": str(cache_dir),
        "PROVIDER_SNAPSHOT_DIR": str(snapshot_dir),
        "ATTACK_ARTIFACT_DIR": str(resource_root / "attack"),
        "DEMO_PROVIDER_SNAPSHOT_ENABLED": "true",
        "DEMO_WORKSPACE_ENABLED": "true",
        "FRONTEND_HOST": "",
        "BACKEND_CORS_ORIGINS": "",
        "ALLOWED_HOSTS": ",".join(dict.fromkeys((host, "localhost", "127.0.0.1", "testserver"))),
        "IN_PROCESS_WORKER_ENABLED": "true" if in_process_worker else "false",
        "API_DOCS_ENABLED": "false",
    }
    for name, value in environment.items():
        os.environ[name] = value
    os.environ.setdefault("WORKER_POLL_INTERVAL_SECONDS", "0.5")
    os.environ.setdefault("RATE_LIMIT_ENABLED", "true")
    os.environ.setdefault("DECISION_LEDGER_SHADOW_READ", "true")
    return root


def _migrate_and_load_settings() -> Any:
    from alembic import command

    from app.core.config import load_settings
    from app.core.migration_bootstrap import _alembic_config

    active_settings = load_settings()
    config = _alembic_config()
    config.set_main_option("sqlalchemy.url", active_settings.SQLALCHEMY_DATABASE_URI)
    command.upgrade(config, "head")
    return active_settings


def _validate_bind(*, host: str, port: int, allow_network: bool) -> None:
    if not 1 <= port <= 65_535:
        raise SystemExit("--port must be between 1 and 65535.")
    if allow_network:
        return
    if host not in {"127.0.0.1", "localhost"}:
        raise SystemExit(
            "vpw serve binds to loopback by default. Use --allow-network only after "
            "reviewing the local single-user security boundary."
        )


def _sqlite_uri(path: Path) -> str:
    rendered = path.resolve(strict=False).as_posix()
    return f"sqlite:///{rendered}"


def _remove_sqlite_files(path: Path) -> None:
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        candidate.unlink(missing_ok=True)


def _ensure_packaged_demo_snapshot(
    snapshot_dir: Path,
    *,
    resource_root: Path | None = None,
) -> None:
    resources_root = resource_root or Path(str(resources.files("app").joinpath("resources")))
    packaged_demo_snapshot = resources_root / "demo_provider_snapshot.json"
    local_demo_snapshot = snapshot_dir / "demo_provider_snapshot.json"
    snapshot_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if packaged_demo_snapshot.is_file() and not local_demo_snapshot.exists():
        shutil.copyfile(packaged_demo_snapshot, local_demo_snapshot)
    if local_demo_snapshot.exists():
        _harden_permissions(local_demo_snapshot, 0o600)


def _migration_source_url(args: argparse.Namespace) -> str:
    if bool(args.source_postgres_env):
        from app.core.config import build_database_uri

        source_url = build_database_uri()
        if not source_url.startswith(("postgresql://", "postgresql+")):
            raise SystemExit(
                "--source-postgres-env requires POSTGRES_SERVER and the matching "
                "POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_PORT, and POSTGRES_DB values."
            )
        return source_url
    source_env = str(args.source_url_env).strip()
    if not source_env or not source_env.replace("_", "A").isalnum() or source_env[0].isdigit():
        raise SystemExit("--source-url-env must name a simple environment variable.")
    source_url = os.environ.get(source_env, "").strip()
    if not source_url:
        raise SystemExit(f"Set {source_env} to the source SQLAlchemy database URL.")
    return source_url


def _harden_permissions(path: Path, mode: int) -> None:
    if os.name == "nt" or not path.exists():
        return
    path.chmod(mode)


def _default_data_dir() -> Path:
    system = platform.system()
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Vuln Prioritizer Workbench"
    if system == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "Vuln Prioritizer Workbench"
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "vuln-prioritizer-workbench"


def _open_browser_when_ready(url: str, *, timeout_seconds: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    health_url = f"{url}/api/v1/utils/health-check/"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(health_url, timeout=1.0) as response:
                if response.status == 200:
                    webbrowser.open(url)
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.2)


def _package_version() -> str:
    try:
        return metadata.version("vuln-prioritizer-workbench")
    except metadata.PackageNotFoundError:
        return "0.0.0+local"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
