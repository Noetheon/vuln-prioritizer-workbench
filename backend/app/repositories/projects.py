"""Project repository for template Workbench persistence."""

from __future__ import annotations

import uuid

from sqlmodel import Session, col, func, select

from app.models import Project, ProjectCreate, ProjectUpdate, User
from app.models.base import get_datetime_utc


class ProjectRepository:
    """Project persistence helpers for API routes and future services."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def list_visible_projects(self, user: User) -> tuple[list[Project], int]:
        """Return projects visible to a user plus the matching total count."""
        count_statement = select(func.count()).select_from(Project)
        statement = select(Project).order_by(col(Project.created_at).desc())
        if not user.is_superuser:
            count_statement = count_statement.where(Project.owner_id == user.id)
            statement = statement.where(Project.owner_id == user.id)

        count = self.session.exec(count_statement).one()
        projects = self.session.exec(statement).all()
        return list(projects), count

    def create_project(self, project_in: ProjectCreate, *, owner_id: uuid.UUID) -> Project:
        """Create a project shell without committing the transaction."""
        project = Project.model_validate(project_in, update={"owner_id": owner_id})
        self.session.add(project)
        self.session.flush()
        return project

    def get_project(self, project_id: uuid.UUID) -> Project | None:
        """Return a project by primary key."""
        return self.session.get(Project, project_id)

    def get_visible_project(self, project_id: uuid.UUID, user: User) -> Project | None:
        """Return a project only when it is visible to the user."""
        project = self.get_project(project_id)
        if project is None:
            return None
        if user.is_superuser or project.owner_id == user.id:
            return project
        return None

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
