"""ATT&CK mapping and finding context persistence helpers."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from vuln_prioritizer.db.models import (
    AttackMappingRecord,
    Finding,
    FindingAttackContext,
)


class AttackRepositoryMixin:
    """Attack repository methods."""

    session: Session

    def upsert_attack_mapping(
        self,
        *,
        vulnerability_id: str,
        cve_id: str,
        attack_object_id: str,
        source: str,
        attack_object_name: str | None = None,
        mapping_type: str | None = None,
        source_version: str | None = None,
        source_hash: str | None = None,
        source_path: str | None = None,
        attack_version: str | None = None,
        domain: str | None = None,
        metadata_hash: str | None = None,
        metadata_path: str | None = None,
        confidence: float | None = None,
        review_status: str = "unreviewed",
        rationale: str | None = None,
        references_json: list[str] | None = None,
        mapping_json: dict | None = None,
    ) -> AttackMappingRecord:
        statement = select(AttackMappingRecord).where(
            AttackMappingRecord.source == source,
            AttackMappingRecord.cve_id == cve_id,
            AttackMappingRecord.attack_object_id == attack_object_id,
            AttackMappingRecord.mapping_type == mapping_type,
        )
        mapping = self.session.scalar(statement)
        if mapping is None:
            mapping = AttackMappingRecord(
                vulnerability_id=vulnerability_id,
                cve_id=cve_id,
                attack_object_id=attack_object_id,
                source=source,
            )
            self.session.add(mapping)
        mapping.vulnerability_id = vulnerability_id
        mapping.attack_object_name = attack_object_name
        mapping.mapping_type = mapping_type
        mapping.source_version = source_version
        mapping.source_hash = source_hash
        mapping.source_path = source_path
        mapping.attack_version = attack_version
        mapping.domain = domain
        mapping.metadata_hash = metadata_hash
        mapping.metadata_path = metadata_path
        mapping.confidence = confidence
        mapping.review_status = review_status
        mapping.rationale = rationale
        mapping.references_json = references_json or []
        mapping.mapping_json = mapping_json or {}
        self.session.flush()
        return mapping

    def create_or_update_finding_attack_context(
        self,
        *,
        finding_id: str,
        analysis_run_id: str,
        cve_id: str,
        mapped: bool,
        source: str,
        attack_relevance: str,
        threat_context_rank: int,
        source_version: str | None = None,
        source_hash: str | None = None,
        source_path: str | None = None,
        attack_version: str | None = None,
        domain: str | None = None,
        metadata_hash: str | None = None,
        metadata_path: str | None = None,
        rationale: str | None = None,
        review_status: str = "unreviewed",
        techniques_json: list[dict[str, Any]] | None = None,
        tactics_json: list[str] | None = None,
        mappings_json: list[dict[str, Any]] | None = None,
    ) -> FindingAttackContext:
        statement = select(FindingAttackContext).where(
            FindingAttackContext.finding_id == finding_id,
            FindingAttackContext.analysis_run_id == analysis_run_id,
        )
        context = self.session.scalar(statement)
        if context is None:
            context = FindingAttackContext(
                finding_id=finding_id,
                analysis_run_id=analysis_run_id,
                cve_id=cve_id,
            )
            self.session.add(context)
        context.cve_id = cve_id
        context.mapped = mapped
        context.source = source
        context.source_version = source_version
        context.source_hash = source_hash
        context.source_path = source_path
        context.attack_version = attack_version
        context.domain = domain
        context.metadata_hash = metadata_hash
        context.metadata_path = metadata_path
        context.attack_relevance = attack_relevance
        context.threat_context_rank = threat_context_rank
        context.rationale = rationale
        context.review_status = review_status
        context.techniques_json = techniques_json or []
        context.tactics_json = tactics_json or []
        context.mappings_json = mappings_json or []
        self.session.flush()
        return context

    def list_finding_attack_contexts(self, finding_id: str) -> list[FindingAttackContext]:
        statement = (
            select(FindingAttackContext)
            .where(FindingAttackContext.finding_id == finding_id)
            .order_by(FindingAttackContext.threat_context_rank, FindingAttackContext.created_at)
        )
        return list(self.session.scalars(statement))

    def list_run_attack_contexts(self, analysis_run_id: str) -> list[FindingAttackContext]:
        statement = (
            select(FindingAttackContext)
            .where(FindingAttackContext.analysis_run_id == analysis_run_id)
            .order_by(FindingAttackContext.threat_context_rank, FindingAttackContext.cve_id)
        )
        return list(self.session.scalars(statement))

    def list_project_attack_contexts(self, project_id: str) -> list[FindingAttackContext]:
        statement = (
            select(FindingAttackContext)
            .join(Finding, Finding.id == FindingAttackContext.finding_id)
            .where(Finding.project_id == project_id)
            .order_by(FindingAttackContext.threat_context_rank, FindingAttackContext.cve_id)
        )
        return list(self.session.scalars(statement))

    def list_project_attack_review_contexts(
        self,
        project_id: str,
        *,
        review_status: str | None = None,
        source: str | None = None,
        mapped: bool | None = None,
        priority: str | None = None,
        technique_id: str | None = None,
        limit: int = 100,
    ) -> list[FindingAttackContext]:
        statement = (
            select(FindingAttackContext)
            .join(Finding, Finding.id == FindingAttackContext.finding_id)
            .where(Finding.project_id == project_id)
            .options(selectinload(FindingAttackContext.finding))
        )
        if review_status is not None:
            statement = statement.where(FindingAttackContext.review_status == review_status)
        if source is not None:
            statement = statement.where(FindingAttackContext.source == source)
        if mapped is not None:
            statement = statement.where(FindingAttackContext.mapped == mapped)
        if priority is not None:
            statement = statement.where(Finding.priority == priority)
        statement = statement.order_by(
            FindingAttackContext.review_status,
            FindingAttackContext.threat_context_rank,
            FindingAttackContext.cve_id,
        )
        contexts = list(self.session.scalars(statement))
        if technique_id is not None:
            contexts = [
                context
                for context in contexts
                if _attack_context_has_technique(context, technique_id)
            ]
        return contexts[:limit]

    def update_finding_attack_review_status(
        self,
        finding_id: str,
        *,
        review_status: str,
    ) -> list[FindingAttackContext]:
        contexts = self.list_finding_attack_contexts(finding_id)
        for context in contexts:
            context.review_status = review_status
        self.session.flush()
        return contexts


def _attack_context_has_technique(context: FindingAttackContext, technique_id: str) -> bool:
    for technique in context.techniques_json or []:
        if isinstance(technique, dict) and technique.get("attack_object_id") == technique_id:
            return True
        if isinstance(technique, dict) and technique.get("technique_id") == technique_id:
            return True
    return False
