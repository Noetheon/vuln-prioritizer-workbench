"""Internal schema smoke used by Docker Compose release checks."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel

from app.core.db import engine, ensure_configured_superuser
from app.core.migration_bootstrap import ALEMBIC_HEAD
from app.models import Project, ProjectCreate, import_table_models
from app.repositories import ProjectRepository


@dataclass(frozen=True)
class SchemaSmokeResult:
    """Compact summary for a successful database schema smoke."""

    dialect: str
    alembic_versions: tuple[str, ...]
    table_count: int
    repository_project_id: uuid.UUID | None = None


def required_model_tables() -> set[str]:
    """Return table names that the current SQLModel metadata expects."""
    import_table_models()
    return {name for name in SQLModel.metadata.tables if name != "alembic_version"}


def assert_postgres_engine(active_engine: Engine) -> str:
    """Require the smoke to run against the Compose Postgres backend."""
    dialect = active_engine.dialect.name
    if dialect != "postgresql":
        raise RuntimeError(
            f"Compose schema smoke must run against PostgreSQL; configured dialect is {dialect!r}."
        )
    return dialect


def assert_migrated_schema(active_engine: Engine) -> SchemaSmokeResult:
    """Validate Alembic head and model tables on the active database."""
    inspector = inspect(active_engine)
    table_names = set(inspector.get_table_names())
    missing_tables = sorted(required_model_tables() - table_names)
    if missing_tables:
        raise RuntimeError(
            "Database schema is missing model tables: " + ", ".join(missing_tables[:20])
        )
    if "alembic_version" not in table_names:
        raise RuntimeError("Database schema is missing alembic_version.")

    with active_engine.connect() as connection:
        versions = tuple(
            sorted(
                str(row[0])
                for row in connection.execute(text("SELECT version_num FROM alembic_version")).all()
            )
        )
    if ALEMBIC_HEAD not in versions:
        found = ", ".join(versions) if versions else "<none>"
        raise RuntimeError(f"Alembic head mismatch: expected {ALEMBIC_HEAD}, found {found}.")

    return SchemaSmokeResult(
        dialect=active_engine.dialect.name,
        alembic_versions=versions,
        table_count=len(table_names),
    )


def run_project_repository_smoke(active_engine: Engine) -> uuid.UUID:
    """Exercise a direct repository create/list/delete cycle on the active DB."""
    project_id: uuid.UUID | None = None
    with Session(active_engine) as session:
        repository = ProjectRepository(session)
        try:
            user = ensure_configured_superuser(session)
            project = repository.create_project(
                ProjectCreate(
                    name=f"compose-postgres-schema-smoke-{uuid.uuid4().hex[:8]}",
                    description="Temporary Compose Postgres repository smoke.",
                ),
                owner_id=user.id,
            )
            project_id = project.id
            session.commit()

            projects, _count = repository.list_visible_projects(user)
            if project_id not in {candidate.id for candidate in projects}:
                raise RuntimeError("Project repository smoke did not list the inserted project.")
            return project_id
        finally:
            session.rollback()
            if project_id is not None:
                persisted = session.get(Project, project_id)
                if persisted is not None:
                    repository.delete_project(persisted)
                    session.commit()


def run_smoke(active_engine: Engine = engine) -> SchemaSmokeResult:
    """Run the full Compose Postgres schema and repository smoke."""
    assert_postgres_engine(active_engine)
    result = assert_migrated_schema(active_engine)
    project_id = run_project_repository_smoke(active_engine)
    return replace(result, repository_project_id=project_id)


def main() -> None:
    """CLI entrypoint for ``python -m app.core.schema_smoke``."""
    result = run_smoke()
    print(
        "Compose Postgres schema smoke passed: "
        f"dialect={result.dialect} "
        f"alembic_versions={','.join(result.alembic_versions)} "
        f"tables={result.table_count} "
        f"repository_project_id={result.repository_project_id}"
    )


if __name__ == "__main__":
    main()
