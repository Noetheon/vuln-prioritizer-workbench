"""Private VEX parsing and matching helpers."""

from __future__ import annotations

from vuln_prioritizer.models import InputOccurrence, VexStatement
from vuln_prioritizer.utils import normalize_cve_id


def parse_openvex_document(document: dict) -> list[VexStatement]:
    """Parse OpenVEX JSON into normalized VEX statements."""
    statements: list[VexStatement] = []
    for index, statement in enumerate(document.get("statements", []), start=1):
        cve_id = normalize_cve_id(statement.get("vulnerability", {}).get("@id"))
        if cve_id is None:
            cve_id = normalize_cve_id(statement.get("vulnerability", {}).get("name"))
        if cve_id is None:
            continue
        for product in statement.get("products", []):
            statements.append(
                VexStatement(
                    source_format="openvex-json",
                    cve_id=cve_id,
                    status=(statement.get("status") or "").strip(),
                    purl=product.get("@id"),
                    target_kind=product.get("subcomponents", [{}])[0].get("kind"),
                    target_ref=product.get("subcomponents", [{}])[0].get("name"),
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
        for component in document.get("components", [])
        if component.get("bom-ref")
    }
    statements: list[VexStatement] = []
    for index, vulnerability in enumerate(document.get("vulnerabilities", []), start=1):
        cve_id = normalize_cve_id(vulnerability.get("id"))
        if cve_id is None:
            continue
        status = vulnerability.get("analysis", {}).get("state")
        if not status:
            continue
        for affect in vulnerability.get("affects", []):
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
                    target_ref=document.get("metadata", {}).get("component", {}).get("name"),
                    justification=vulnerability.get("analysis", {}).get("justification"),
                    action_statement=vulnerability.get("analysis", {}).get("response", [None])[0],
                    source_record_id=f"vulnerability:{index}",
                )
            )
    return statements


def apply_vex_statements(
    occurrences: list[InputOccurrence],
    statements: list[VexStatement],
) -> list[InputOccurrence]:
    """Apply the first matching VEX statement to each occurrence."""
    if not statements:
        return occurrences

    resolved: list[InputOccurrence] = []
    for occurrence in occurrences:
        matched_statement = match_vex_statement(occurrence, statements)
        if matched_statement is None:
            resolved.append(occurrence)
            continue
        resolved.append(
            occurrence.model_copy(
                update={
                    "vex_status": matched_statement.status,
                    "vex_justification": matched_statement.justification,
                    "vex_action_statement": matched_statement.action_statement,
                }
            )
        )
    return resolved


def match_vex_statement(
    occurrence: InputOccurrence,
    statements: list[VexStatement],
) -> VexStatement | None:
    """Return the first VEX statement matching an occurrence."""
    for statement in statements:
        if statement.cve_id != occurrence.cve_id:
            continue
        if statement.purl and occurrence.purl and statement.purl == occurrence.purl:
            return statement
        if (
            statement.component_name
            and occurrence.component_name
            and statement.component_name == occurrence.component_name
            and (
                statement.component_version is None
                or occurrence.component_version is None
                or statement.component_version == occurrence.component_version
            )
        ):
            return statement
        if (
            statement.target_kind
            and statement.target_ref
            and occurrence.target_ref
            and statement.target_kind.lower() == occurrence.target_kind.lower()
            and statement.target_ref == occurrence.target_ref
        ):
            return statement
    return None
