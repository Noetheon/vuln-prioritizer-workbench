from __future__ import annotations

from vuln_prioritizer.inputs._vex_support import (
    apply_vex_statements,
    match_vex_statement_details,
)
from vuln_prioritizer.models import InputOccurrence, VexStatement


def _occurrence() -> InputOccurrence:
    return InputOccurrence(
        cve_id="CVE-2024-1234",
        source_format="cve-list",
        component_name="libfoo",
        component_version="1.2.3",
        purl="pkg:generic/libfoo@1.2.3",
        target_kind="repository",
        target_ref="repo-a",
    )


def _statement(
    *,
    status: str,
    purl: str | None = None,
    component_name: str | None = None,
    component_version: str | None = None,
    target_kind: str | None = None,
    target_ref: str | None = None,
) -> VexStatement:
    return VexStatement(
        source_format="openvex-json",
        cve_id="CVE-2024-1234",
        status=status,
        purl=purl,
        component_name=component_name,
        component_version=component_version,
        target_kind=target_kind,
        target_ref=target_ref,
    )


def test_ranked_vex_matching_prefers_more_specific_statement_over_earlier_generic_match() -> None:
    occurrence = _occurrence()
    statements = [
        _statement(status="fixed", purl=occurrence.purl),
        _statement(
            status="under_investigation",
            purl=occurrence.purl,
            target_kind=occurrence.target_kind,
            target_ref=occurrence.target_ref,
        ),
        _statement(
            status="not_affected",
            component_name=occurrence.component_name,
            component_version=occurrence.component_version,
            target_kind=occurrence.target_kind,
            target_ref=occurrence.target_ref,
        ),
    ]

    match = match_vex_statement_details(occurrence, statements)

    assert match is not None
    assert match.specificity == "purl+target"
    assert match.statement_index == 1
    assert match.candidate_count == 3
    assert match.statement.status == "under_investigation"

    resolved = apply_vex_statements([occurrence], statements)
    assert resolved[0].vex_status == "under_investigation"


def test_ranked_vex_matching_uses_earlier_statement_when_specificity_ties() -> None:
    occurrence = _occurrence()
    statements = [
        _statement(
            status="under_investigation",
            purl=occurrence.purl,
            target_kind=occurrence.target_kind,
            target_ref=occurrence.target_ref,
        ),
        _statement(
            status="not_affected",
            purl=occurrence.purl,
            target_kind=occurrence.target_kind,
            target_ref=occurrence.target_ref,
        ),
    ]

    match = match_vex_statement_details(occurrence, statements)

    assert match is not None
    assert match.specificity == "purl+target"
    assert match.statement_index == 0
    assert match.candidate_count == 2
    assert match.same_rank_conflict_count == 1
    assert match.statement.status == "under_investigation"

    resolved = apply_vex_statements([occurrence], statements)
    assert resolved[0].vex_status == "under_investigation"
