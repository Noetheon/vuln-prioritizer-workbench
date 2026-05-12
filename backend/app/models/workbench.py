"""Workbench status DTOs."""

from sqlmodel import SQLModel


class WorkbenchStatus(SQLModel):
    """Status response returned by the active Workbench runtime."""

    status: str
    app: str
    core_package: str
    core_version: str
    database_status: str
    schema_status: str


class WorkbenchHealth(SQLModel):
    """Minimal local health response."""

    status: str
