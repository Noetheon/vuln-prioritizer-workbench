"""
Enforce stable finding identity for GitHub issue exports.

Revision ID: 20260904_0007
Revises: 20260904_0006
Create Date: 2026-09-04 01:00:00.000000
"""

from __future__ import annotations

from urllib.parse import urlparse

import sqlalchemy as sa
from alembic import op

revision = "20260904_0007"
down_revision = "20260904_0006"
branch_labels = None
depends_on = None

_FINDING_IDENTITY_CONSTRAINT = "uq_github_issue_export_project_repository_finding"
_DUPLICATE_IDENTITY_CONSTRAINT = "uq_github_issue_export_project_repository_duplicate"
_LEGACY_ALIAS_MARKER = ":legacy-case-alias:"
_DUPLICATE_KEY_MAX_LENGTH = 512


def upgrade() -> None:
    """
    Link at most one export row to each project/repository/finding identity.

    Legacy duplicate rows remain as immutable external-issue history, but only
    the preferred completed row retains its finding link. Completed exports
    win over incomplete reservations; ties use creation time and row ID.
    """
    _start_portable_write_transaction()
    with op.batch_alter_table("github_issue_export") as batch_op:
        batch_op.drop_constraint(_DUPLICATE_IDENTITY_CONSTRAINT, type_="unique")
    _canonicalize_repository_aliases()
    _detach_duplicate_finding_links()
    with op.batch_alter_table("github_issue_export") as batch_op:
        batch_op.create_unique_constraint(
            _DUPLICATE_IDENTITY_CONSTRAINT,
            ["project_id", "repository", "duplicate_key"],
        )
        batch_op.create_unique_constraint(
            _FINDING_IDENTITY_CONSTRAINT,
            ["project_id", "repository", "finding_id"],
        )


def downgrade() -> None:
    """Remove the stable finding-link constraint without recreating duplicate links."""
    _start_portable_write_transaction()
    with op.batch_alter_table("github_issue_export") as batch_op:
        batch_op.drop_constraint(_FINDING_IDENTITY_CONSTRAINT, type_="unique")


def _start_portable_write_transaction() -> None:
    """Start SQLite's transaction before data changes and batch DDL."""
    connection = op.get_bind()
    metadata = sa.MetaData()
    export = sa.Table(
        "github_issue_export",
        metadata,
        autoload_with=connection,
        resolve_fks=False,
    )
    connection.execute(sa.update(export).where(sa.false()).values(id=export.c.id))


def _detach_duplicate_finding_links() -> None:
    """Preserve every legacy row while retaining one canonical finding link."""
    connection = op.get_bind()
    metadata = sa.MetaData()
    export = sa.Table(
        "github_issue_export",
        metadata,
        autoload_with=connection,
        resolve_fks=False,
    )
    completed_first = sa.case(
        (
            sa.and_(
                export.c.issue_url.is_not(None),
                export.c.issue_url != "",
                export.c.issue_number.is_not(None),
                export.c.issue_number > 0,
            ),
            0,
        ),
        else_=1,
    )
    rows = connection.execute(
        sa.select(
            export.c.id,
            export.c.project_id,
            export.c.repository,
            export.c.finding_id,
        )
        .where(export.c.finding_id.is_not(None))
        .order_by(
            export.c.project_id,
            export.c.repository,
            export.c.finding_id,
            completed_first,
            export.c.created_at,
            export.c.id,
        )
    ).mappings()
    seen: set[tuple[object, str, object]] = set()
    duplicate_ids: list[object] = []
    for row in rows:
        identity = (row["project_id"], row["repository"], row["finding_id"])
        if identity in seen:
            duplicate_ids.append(row["id"])
        else:
            seen.add(identity)
    for duplicate_id in duplicate_ids:
        connection.execute(
            sa.update(export).where(export.c.id == duplicate_id).values(finding_id=None)
        )


def _canonicalize_repository_aliases() -> None:
    """Casefold GitHub repositories and retain colliding legacy rows safely."""
    connection = op.get_bind()
    metadata = sa.MetaData()
    export = sa.Table(
        "github_issue_export",
        metadata,
        autoload_with=connection,
        resolve_fks=False,
    )
    rows = list(
        connection.execute(
            sa.select(
                export.c.id,
                export.c.project_id,
                export.c.repository,
                export.c.duplicate_key,
                export.c.issue_url,
                export.c.issue_number,
                export.c.created_at,
            )
        ).mappings()
    )
    rows.sort(
        key=lambda row: (
            str(row["project_id"]),
            str(row["repository"]).casefold(),
            str(row["duplicate_key"]),
            (
                0
                if _valid_completed_issue(
                    str(row["repository"]),
                    row["issue_url"],
                    row["issue_number"],
                )
                else 1
            ),
            str(row["created_at"]),
            str(row["id"]),
        )
    )
    seen: set[tuple[str, str, str]] = set()
    used_keys: set[tuple[str, str, str]] = {
        (
            str(row["project_id"]),
            str(row["repository"]).casefold(),
            str(row["duplicate_key"]),
        )
        for row in rows
    }
    for row in rows:
        project_id = str(row["project_id"])
        repository = str(row["repository"]).casefold()
        duplicate_key = str(row["duplicate_key"])
        identity = (project_id, repository, duplicate_key)
        values: dict[str, object] = {"repository": repository}
        if not _valid_completed_issue(repository, row["issue_url"], row["issue_number"]):
            values.update(issue_url=None, issue_number=None)
        if identity in seen:
            duplicate_key = _legacy_duplicate_key(
                duplicate_key,
                row_id=row["id"],
                project_id=project_id,
                repository=repository,
                used_keys=used_keys,
            )
            values.update(duplicate_key=duplicate_key, finding_id=None)
        else:
            seen.add(identity)
        connection.execute(sa.update(export).where(export.c.id == row["id"]).values(**values))


def _valid_completed_issue(repository: str, issue_url: object, issue_number: object) -> bool:
    """Recognize only exact GitHub issue identities in untrusted legacy rows."""
    if (
        not isinstance(issue_url, str)
        or not isinstance(issue_number, int)
        or isinstance(issue_number, bool)
        or issue_number <= 0
    ):
        return False
    parsed_url = urlparse(issue_url)
    return (
        parsed_url.scheme == "https"
        and parsed_url.netloc.casefold() == "github.com"
        and parsed_url.path.casefold() == f"/{repository.casefold()}/issues/{issue_number}"
        and not parsed_url.params
        and not parsed_url.query
        and not parsed_url.fragment
    )


def _legacy_duplicate_key(
    duplicate_key: str,
    *,
    row_id: object,
    project_id: str,
    repository: str,
    used_keys: set[tuple[str, str, str]],
) -> str:
    """Create one deterministic, bounded history-only duplicate key."""
    suffix = f"{_LEGACY_ALIAS_MARKER}{row_id}"
    base = duplicate_key[: _DUPLICATE_KEY_MAX_LENGTH - len(suffix)]
    candidate = f"{base}{suffix}"
    counter = 1
    while (project_id, repository, candidate) in used_keys:
        counter_suffix = f":{counter}"
        available = _DUPLICATE_KEY_MAX_LENGTH - len(suffix) - len(counter_suffix)
        candidate = f"{base[:available]}{suffix}{counter_suffix}"
        counter += 1
    used_keys.add((project_id, repository, candidate))
    return candidate
