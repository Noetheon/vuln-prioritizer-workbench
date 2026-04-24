"""Private VEX parsing and matching helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, overload

from vuln_prioritizer.models import InputOccurrence, VexStatement
from vuln_prioritizer.utils import normalize_cve_id

OPENVEX_STATUS_MAP = {
    "affected": "affected",
    "fixed": "fixed",
    "not_affected": "not_affected",
    "under_investigation": "under_investigation",
}

CYCLONEDX_STATE_MAP = {
    "affected": "affected",
    "exploitable": "affected",
    "false_positive": "not_affected",
    "fixed": "fixed",
    "in_triage": "under_investigation",
    "not_affected": "not_affected",
    "resolved": "fixed",
    "resolved_with_pedigree": "fixed",
}


@dataclass(frozen=True)
class VexMatchResult:
    """Details about the selected VEX match for an occurrence."""

    statement: VexStatement
    specificity: str
    specificity_rank: int
    statement_index: int
    candidate_count: int = 0
    same_rank_conflict_count: int = 0


@dataclass(frozen=True)
class VexMatchDiagnostics:
    matched_occurrences: int
    unmatched_occurrences: int
    ambiguous_occurrences: int
    conflict_occurrences: int
    warnings: tuple[str, ...] = ()


def parse_openvex_document(document: dict) -> list[VexStatement]:
    """Parse OpenVEX JSON into normalized VEX statements."""
    statements: list[VexStatement] = []
    for index, statement in enumerate(_dict_items(document.get("statements")), start=1):
        vulnerability = _dict_value(statement.get("vulnerability"))
        cve_id = normalize_cve_id(vulnerability.get("@id"))
        if cve_id is None:
            cve_id = normalize_cve_id(vulnerability.get("name"))
        if cve_id is None:
            continue
        status = _normalize_vex_status(
            statement.get("status"),
            status_map=OPENVEX_STATUS_MAP,
        )
        if status is None:
            continue
        for product in _dict_items(statement.get("products")):
            subcomponents = _dict_items(product.get("subcomponents"))
            if not subcomponents:
                statements.append(
                    VexStatement(
                        source_format="openvex-json",
                        cve_id=cve_id,
                        status=status,
                        purl=product.get("@id"),
                        justification=statement.get("justification"),
                        action_statement=statement.get("action_statement"),
                        source_record_id=f"statement:{index}",
                    )
                )
                continue
            for subcomponent in subcomponents:
                statements.append(
                    VexStatement(
                        source_format="openvex-json",
                        cve_id=cve_id,
                        status=status,
                        purl=product.get("@id"),
                        target_kind=subcomponent.get("kind"),
                        target_ref=subcomponent.get("name"),
                        justification=statement.get("justification"),
                        action_statement=statement.get("action_statement"),
                        source_record_id=f"statement:{index}",
                    )
                )
    return statements


def parse_cyclonedx_vex_document(document: dict) -> list[VexStatement]:
    """Parse CycloneDX VEX JSON into normalized VEX statements."""
    components = {
        component.get("bom-ref"): component
        for component in _dict_items(document.get("components"))
        if component.get("bom-ref")
    }
    metadata = _dict_value(document.get("metadata"))
    root_component = _dict_value(metadata.get("component"))
    statements: list[VexStatement] = []
    for index, vulnerability in enumerate(_dict_items(document.get("vulnerabilities")), start=1):
        cve_id = normalize_cve_id(vulnerability.get("id"))
        if cve_id is None:
            continue
        analysis = vulnerability.get("analysis")
        analysis = analysis if isinstance(analysis, dict) else {}
        status = _normalize_vex_status(
            analysis.get("state"),
            status_map=CYCLONEDX_STATE_MAP,
        )
        if status is None:
            continue
        action_statement = _first_string(analysis.get("response"))
        for affect in _dict_items(vulnerability.get("affects")):
            component = components.get(affect.get("ref"), {})
            statements.append(
                VexStatement(
                    source_format="cyclonedx-vex-json",
                    cve_id=cve_id,
                    status=status,
                    component_name=component.get("name"),
                    component_version=component.get("version"),
                    purl=component.get("purl"),
                    target_kind="repository",
                    target_ref=root_component.get("name"),
                    justification=analysis.get("justification"),
                    action_statement=action_statement,
                    source_record_id=f"vulnerability:{index}",
                )
            )
    return statements


@overload
def apply_vex_statements(
    occurrences: list[InputOccurrence],
    statements: list[VexStatement],
    *,
    return_diagnostics: Literal[False] = False,
) -> list[InputOccurrence]:
    raise NotImplementedError


@overload
def apply_vex_statements(
    occurrences: list[InputOccurrence],
    statements: list[VexStatement],
    *,
    return_diagnostics: Literal[True],
) -> tuple[list[InputOccurrence], VexMatchDiagnostics]:
    raise NotImplementedError


def apply_vex_statements(
    occurrences: list[InputOccurrence],
    statements: list[VexStatement],
    *,
    return_diagnostics: bool = False,
) -> list[InputOccurrence] | tuple[list[InputOccurrence], VexMatchDiagnostics]:
    """Apply the best matching VEX statement to each occurrence."""
    if not statements:
        diagnostics = VexMatchDiagnostics(
            matched_occurrences=0,
            unmatched_occurrences=len(occurrences),
            ambiguous_occurrences=0,
            conflict_occurrences=0,
        )
        return (occurrences, diagnostics) if return_diagnostics else occurrences

    resolved: list[InputOccurrence] = []
    matched_occurrences = 0
    unmatched_occurrences = 0
    ambiguous_occurrences = 0
    conflict_occurrences = 0
    for occurrence in occurrences:
        matched_statement = match_vex_statement_details(occurrence, statements)
        if matched_statement is None:
            unmatched_occurrences += 1
            resolved.append(occurrence)
            continue
        matched_occurrences += 1
        if matched_statement.candidate_count > 1:
            ambiguous_occurrences += 1
        if matched_statement.same_rank_conflict_count:
            conflict_occurrences += 1
        resolved.append(
            occurrence.model_copy(
                update={
                    "vex_status": matched_statement.statement.status,
                    "vex_justification": matched_statement.statement.justification,
                    "vex_action_statement": matched_statement.statement.action_statement,
                    "vex_match_type": matched_statement.specificity,
                    "vex_source_format": matched_statement.statement.source_format,
                    "vex_source_record_id": matched_statement.statement.source_record_id,
                    "vex_source_path": matched_statement.statement.source_path,
                    "vex_candidate_count": matched_statement.candidate_count,
                }
            )
        )

    warning_messages: list[str] = []
    if conflict_occurrences:
        warning_messages.append(
            "VEX resolved "
            f"{conflict_occurrences} occurrence(s) with conflicting same-rank statements "
            "using file order and statement order."
        )
    diagnostics = VexMatchDiagnostics(
        matched_occurrences=matched_occurrences,
        unmatched_occurrences=unmatched_occurrences,
        ambiguous_occurrences=ambiguous_occurrences,
        conflict_occurrences=conflict_occurrences,
        warnings=tuple(warning_messages),
    )
    return (resolved, diagnostics) if return_diagnostics else resolved


def match_vex_statement(
    occurrence: InputOccurrence,
    statements: list[VexStatement],
) -> VexStatement | None:
    """Return the best VEX statement matching an occurrence."""
    matched_statement = match_vex_statement_details(occurrence, statements)
    return None if matched_statement is None else matched_statement.statement


def match_vex_statement_details(
    occurrence: InputOccurrence,
    statements: list[VexStatement],
) -> VexMatchResult | None:
    """Return the ranked VEX match details for an occurrence."""
    candidates: list[VexMatchResult] = []
    for statement_index, statement in enumerate(statements):
        specificity = _statement_specificity(statement, occurrence)
        if specificity is None:
            continue
        candidates.append(
            VexMatchResult(
                statement=statement,
                specificity=specificity[0],
                specificity_rank=specificity[1],
                statement_index=statement_index,
            )
        )
    if not candidates:
        return None

    candidates.sort(
        key=lambda candidate: (
            candidate.specificity_rank,
            candidate.statement.source_file_order or 0,
            candidate.statement.statement_order or candidate.statement_index,
            candidate.statement_index,
        )
    )
    best_match = candidates[0]
    same_rank_conflicts = sum(
        1 for candidate in candidates if candidate.specificity_rank == best_match.specificity_rank
    )
    return VexMatchResult(
        statement=best_match.statement,
        specificity=best_match.specificity,
        specificity_rank=best_match.specificity_rank,
        statement_index=best_match.statement_index,
        candidate_count=len(candidates),
        same_rank_conflict_count=max(same_rank_conflicts - 1, 0),
    )


def _statement_specificity(
    statement: VexStatement,
    occurrence: InputOccurrence,
) -> tuple[str, int] | None:
    if statement.cve_id != occurrence.cve_id:
        return None
    if _has_version_fields(statement) and not _component_version_matches(statement, occurrence):
        return None

    if _purl_matches(statement, occurrence) and _target_matches(statement, occurrence):
        return "purl+target", _specificity_rank("purl+target")
    if _purl_matches(statement, occurrence) and not _has_target_fields(statement):
        return "purl", _specificity_rank("purl")
    if (
        _component_name_matches(statement, occurrence)
        and statement.component_version is not None
        and _target_matches(statement, occurrence)
        and _component_version_matches(statement, occurrence)
    ):
        return "component+version+target", _specificity_rank("component+version+target")
    if (
        _component_name_matches(statement, occurrence)
        and statement.component_version is not None
        and not _has_target_fields(statement)
        and _component_version_matches(statement, occurrence)
    ):
        return "component+version", _specificity_rank("component+version")
    if _component_name_matches(statement, occurrence) and _target_matches(statement, occurrence):
        return "component+target", _specificity_rank("component+target")
    if (
        _component_name_matches(statement, occurrence)
        and not _has_version_fields(statement)
        and not _has_target_fields(statement)
    ):
        return "component", _specificity_rank("component")
    if (
        _target_matches(statement, occurrence)
        and not _has_component_fields(statement)
        and not statement.purl
    ):
        return "target", _specificity_rank("target")
    return None


def _specificity_rank(specificity: str) -> int:
    return {
        "purl+target": 0,
        "purl": 1,
        "component+version+target": 2,
        "component+version": 3,
        "component+target": 4,
        "component": 5,
        "target": 6,
    }[specificity]


def _purl_matches(statement: VexStatement, occurrence: InputOccurrence) -> bool:
    return bool(statement.purl and occurrence.purl and statement.purl == occurrence.purl)


def _component_name_matches(statement: VexStatement, occurrence: InputOccurrence) -> bool:
    return bool(
        statement.component_name
        and occurrence.component_name
        and statement.component_name == occurrence.component_name
    )


def _component_version_matches(statement: VexStatement, occurrence: InputOccurrence) -> bool:
    if statement.component_version is None:
        return True
    if occurrence.component_version is None:
        return False
    return statement.component_version == occurrence.component_version


def _target_matches(statement: VexStatement, occurrence: InputOccurrence) -> bool:
    return bool(
        statement.target_kind
        and statement.target_ref
        and occurrence.target_ref
        and statement.target_kind.lower() == occurrence.target_kind.lower()
        and statement.target_ref == occurrence.target_ref
    )


def _has_target_fields(statement: VexStatement) -> bool:
    return bool(statement.target_kind and statement.target_ref)


def _has_component_fields(statement: VexStatement) -> bool:
    return bool(statement.component_name)


def _has_version_fields(statement: VexStatement) -> bool:
    return statement.component_version is not None


def _normalize_vex_status(
    value: object,
    *,
    status_map: dict[str, str],
) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower().replace("-", "_")
    return status_map.get(normalized)


def _dict_items(value: object) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _first_dict(value: object) -> dict | None:
    if not isinstance(value, list):
        return None
    for item in value:
        if isinstance(item, dict):
            return item
    return None


def _dict_value(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _first_string(value: object) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    if not isinstance(value, list):
        return None
    for item in value:
        if isinstance(item, str) and item.strip():
            return item.strip()
    return None
