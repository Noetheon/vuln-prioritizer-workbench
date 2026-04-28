"""Central table-model imports for SQLModel metadata and Alembic."""

from importlib import import_module

TABLE_MODEL_MODULES = (
    "app.models.users",
    "app.models.projects",
)


def import_table_models() -> None:
    """Import every module that declares SQLModel table classes."""
    for module_name in TABLE_MODEL_MODULES:
        import_module(module_name)
