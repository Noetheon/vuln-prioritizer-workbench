"""Workbench status DTOs."""

from sqlmodel import SQLModel


class WorkbenchStatus(SQLModel):
    """Status response returned by the active Workbench runtime."""

    status: str
    app: str
    core_package: str
    core_version: str
