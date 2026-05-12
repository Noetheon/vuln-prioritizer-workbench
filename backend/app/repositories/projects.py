"""Project repository for Workbench persistence."""

from __future__ import annotations

import uuid

from sqlmodel import Session, col, func, select

from app.models import Project, ProjectCreate, ProjectUpdate
from app.models.base import get_datetime_utc


class ProjectRepository:
    """Project persistence helpers for API routes and future services."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def list_projects(self) -> tuple[list[Project], int]:
        """Return every local Workbench project."""
        count_statement = select(func.count()).select_from(Project)
        statement = select(Project).order_by(col(Project.created_at).desc())

        count = self.session.exec(count_statement).one()
        projects = self.session.exec(statement).all()
        return list(projects), count

    def create_project(self, project_in: ProjectCreate) -> Project:
        """Create a project shell without committing the transaction."""
        project = Project.model_validate(project_in)
        self.session.add(project)
        self.session.flush()
        return project

    def get_project(self, project_id: uuid.UUID) -> Project | None:
        """Return a project by primary key."""
        return self.session.get(Project, project_id)

    def update_project(self, project: Project, project_in: ProjectUpdate) -> Project:
        """Update mutable project fields without committing the transaction."""
        update_data = project_in.model_dump(exclude_unset=True)
        project.sqlmodel_update(update_data)
        project.updated_at = get_datetime_utc()
        self.session.add(project)
        self.session.flush()
        return project

    def delete_project(self, project: Project) -> None:
        """Delete a project without committing the transaction."""
        self.session.delete(project)
        self.session.flush()
