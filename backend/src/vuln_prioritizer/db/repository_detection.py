"""Detection control persistence helpers."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from vuln_prioritizer.db.models import (
    DetectionControl,
    DetectionControlAttachment,
    DetectionControlHistory,
)


class DetectionControlRepositoryMixin:
    """DetectionControl repository methods."""

    session: Session

    def upsert_detection_control(
        self,
        *,
        project_id: str,
        name: str,
        technique_id: str,
        control_id: str | None = None,
        technique_name: str | None = None,
        source_type: str | None = None,
        coverage_level: str = "unknown",
        environment: str | None = None,
        owner: str | None = None,
        evidence_ref: str | None = None,
        evidence_refs_json: list[str] | None = None,
        review_status: str = "unreviewed",
        notes: str | None = None,
        last_verified_at: str | None = None,
        history_actor: str | None = None,
        history_reason: str | None = None,
    ) -> DetectionControl:
        statement = select(DetectionControl).where(
            DetectionControl.project_id == project_id,
            DetectionControl.technique_id == technique_id,
        )
        if control_id is not None:
            statement = statement.where(DetectionControl.control_id == control_id)
        else:
            statement = statement.where(DetectionControl.control_id.is_(None))
        control = self.session.scalar(statement)
        if control is None:
            control = DetectionControl(
                project_id=project_id,
                name=name,
                technique_id=technique_id,
                control_id=control_id,
            )
            self.session.add(control)
            previous: dict[str, Any] = {}
            event_type = "created"
        else:
            previous = _detection_control_history_snapshot(control)
            event_type = "updated"
        control.name = name
        control.technique_name = technique_name
        control.source_type = source_type
        control.coverage_level = coverage_level
        control.environment = environment
        control.owner = owner
        control.evidence_ref = evidence_ref
        control.evidence_refs_json = evidence_refs_json or []
        control.review_status = review_status
        control.notes = notes
        control.last_verified_at = last_verified_at
        self.session.flush()
        current = _detection_control_history_snapshot(control)
        if previous != current:
            self.add_detection_control_history(
                control=control,
                event_type=event_type,
                actor=history_actor,
                reason=history_reason,
                previous_json=previous,
                current_json=current,
            )
        return control

    def update_detection_control(
        self,
        control: DetectionControl,
        *,
        name: str,
        technique_id: str,
        control_id: str | None = None,
        technique_name: str | None = None,
        source_type: str | None = None,
        coverage_level: str = "unknown",
        environment: str | None = None,
        owner: str | None = None,
        evidence_ref: str | None = None,
        evidence_refs_json: list[str] | None = None,
        review_status: str = "unreviewed",
        notes: str | None = None,
        last_verified_at: str | None = None,
        history_actor: str | None = None,
        history_reason: str | None = None,
    ) -> DetectionControl:
        existing = self.session.scalar(
            select(DetectionControl).where(
                DetectionControl.project_id == control.project_id,
                DetectionControl.technique_id == technique_id,
                DetectionControl.control_id == control_id,
                DetectionControl.id != control.id,
            )
        )
        if existing is not None:
            raise ValueError("Detection control identity already exists.")
        previous = _detection_control_history_snapshot(control)
        control.name = name
        control.technique_id = technique_id
        control.control_id = control_id
        control.technique_name = technique_name
        control.source_type = source_type
        control.coverage_level = coverage_level
        control.environment = environment
        control.owner = owner
        control.evidence_ref = evidence_ref
        control.evidence_refs_json = evidence_refs_json or []
        control.review_status = review_status
        control.notes = notes
        control.last_verified_at = last_verified_at
        self.session.flush()
        current = _detection_control_history_snapshot(control)
        if previous != current:
            self.add_detection_control_history(
                control=control,
                event_type="updated",
                actor=history_actor,
                reason=history_reason,
                previous_json=previous,
                current_json=current,
            )
        return control

    def list_project_detection_controls(self, project_id: str) -> list[DetectionControl]:
        statement = (
            select(DetectionControl)
            .where(DetectionControl.project_id == project_id)
            .options(
                selectinload(DetectionControl.history),
                selectinload(DetectionControl.attachments),
            )
            .order_by(DetectionControl.technique_id, DetectionControl.name)
        )
        return list(self.session.scalars(statement))

    def list_detection_controls_for_technique(
        self, project_id: str, technique_id: str
    ) -> list[DetectionControl]:
        statement = (
            select(DetectionControl)
            .where(
                DetectionControl.project_id == project_id,
                DetectionControl.technique_id == technique_id,
            )
            .options(
                selectinload(DetectionControl.history),
                selectinload(DetectionControl.attachments),
            )
            .order_by(DetectionControl.coverage_level, DetectionControl.name)
        )
        return list(self.session.scalars(statement))

    def get_detection_control(self, control_id: str) -> DetectionControl | None:
        statement = (
            select(DetectionControl)
            .where(DetectionControl.id == control_id)
            .options(
                selectinload(DetectionControl.history),
                selectinload(DetectionControl.attachments),
            )
        )
        return self.session.scalar(statement)

    def delete_detection_control(self, control: DetectionControl) -> None:
        self.session.delete(control)
        self.session.flush()

    def add_detection_control_history(
        self,
        *,
        control: DetectionControl,
        event_type: str,
        actor: str | None = None,
        reason: str | None = None,
        previous_json: dict[str, Any] | None = None,
        current_json: dict[str, Any] | None = None,
    ) -> DetectionControlHistory:
        history = DetectionControlHistory(
            project_id=control.project_id,
            control_id=control.id,
            event_type=event_type,
            actor=actor,
            reason=reason,
            previous_json=previous_json or {},
            current_json=current_json or _detection_control_history_snapshot(control),
        )
        self.session.add(history)
        self.session.flush()
        if "history" in control.__dict__:
            control.history.append(history)
        return history

    def list_detection_control_history(self, control_id: str) -> list[DetectionControlHistory]:
        statement = (
            select(DetectionControlHistory)
            .where(DetectionControlHistory.control_id == control_id)
            .order_by(DetectionControlHistory.created_at.desc())
        )
        return list(self.session.scalars(statement))

    def add_detection_control_attachment(
        self,
        *,
        control_id: str,
        project_id: str,
        filename: str,
        path: str,
        sha256: str,
        size_bytes: int,
        content_type: str | None = None,
    ) -> DetectionControlAttachment:
        attachment = DetectionControlAttachment(
            control_id=control_id,
            project_id=project_id,
            filename=filename,
            content_type=content_type,
            path=path,
            sha256=sha256,
            size_bytes=size_bytes,
        )
        self.session.add(attachment)
        self.session.flush()
        return attachment

    def get_detection_control_attachment(
        self, attachment_id: str
    ) -> DetectionControlAttachment | None:
        return self.session.get(DetectionControlAttachment, attachment_id)

    def list_detection_control_attachments(
        self, control_id: str
    ) -> list[DetectionControlAttachment]:
        statement = (
            select(DetectionControlAttachment)
            .where(DetectionControlAttachment.control_id == control_id)
            .order_by(DetectionControlAttachment.created_at.desc())
        )
        return list(self.session.scalars(statement))

    def delete_detection_control_attachment(self, attachment: DetectionControlAttachment) -> None:
        self.session.delete(attachment)
        self.session.flush()


def _detection_control_history_snapshot(control: DetectionControl) -> dict[str, Any]:
    return {
        "control_id": control.control_id,
        "name": control.name,
        "technique_id": control.technique_id,
        "technique_name": control.technique_name,
        "source_type": control.source_type,
        "coverage_level": control.coverage_level,
        "environment": control.environment,
        "owner": control.owner,
        "evidence_ref": control.evidence_ref,
        "evidence_refs": list(control.evidence_refs_json or []),
        "review_status": control.review_status,
        "notes": control.notes,
        "last_verified_at": control.last_verified_at,
    }
