"""Central table-model imports for SQLModel metadata and Alembic."""

from importlib import import_module

TABLE_MODEL_MODULES = (
    "app.models.projects",
    "app.models.assets",
    "app.models.vulnerabilities",
    "app.models.findings",
    "app.models.runs",
    "app.models.evidence",
    "app.models.reports",
    "app.models.workflows",
    "app.models.audit",
    "app.models.runtime",
    "app.models.github_issues",
    "app.models.attack",
    "app.models.waivers",
)


def import_table_models() -> None:
    """Import every module that declares SQLModel table classes."""
    for module_name in TABLE_MODEL_MODULES:
        import_module(module_name)
