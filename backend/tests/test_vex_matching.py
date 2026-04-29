from __future__ import annotations

from vuln_prioritizer.inputs._vex_support import (
    apply_vex_statements,
    match_vex_statement_details,
    parse_cyclonedx_vex_document,
    parse_openvex_document,
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


def test_version_specific_vex_statement_does_not_match_unknown_occurrence_version() -> None:
    occurrence = _occurrence().model_copy(update={"component_version": None, "purl": None})
    statements = [
        _statement(
            status="fixed",
            component_name=occurrence.component_name,
            component_version="1.2.3",
        )
    ]

    assert match_vex_statement_details(occurrence, statements) is None

    resolved = apply_vex_statements([occurrence], statements)
    assert resolved[0].vex_status is None


def test_version_specific_vex_statement_rejects_mismatched_occurrence_version() -> None:
    occurrence = _occurrence().model_copy(update={"component_version": "2.0.0", "purl": None})
    statements = [
        _statement(
            status="not_affected",
            component_name=occurrence.component_name,
            component_version="1.2.3",
        )
    ]

    assert match_vex_statement_details(occurrence, statements) is None


def test_version_specific_vex_statement_does_not_fall_back_to_target_match() -> None:
    occurrence = _occurrence().model_copy(update={"component_version": None, "purl": None})
    statement = _statement(
        status="not_affected",
        component_name=occurrence.component_name,
        component_version="1.2.3",
        target_kind=occurrence.target_kind,
        target_ref=occurrence.target_ref,
    )

    assert match_vex_statement_details(occurrence, [statement]) is None

    mismatched_occurrence = occurrence.model_copy(update={"component_version": "2.0.0"})
    assert match_vex_statement_details(mismatched_occurrence, [statement]) is None


def test_openvex_parser_tolerates_empty_subcomponents_and_normalizes_status() -> None:
    statements = parse_openvex_document(
        {
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2024-1234"},
                    "status": "under-investigation",
                    "products": [{"@id": "pkg:generic/libfoo@1.2.3", "subcomponents": []}],
                },
                {
                    "vulnerability": {"name": "CVE-2024-5678"},
                    "status": "unsupported-status",
                    "products": [{"@id": "pkg:generic/libbar@1.0.0"}],
                },
            ]
        }
    )

    assert len(statements) == 1
    assert statements[0].status == "under_investigation"
    assert statements[0].target_kind is None
    assert statements[0].target_ref is None


def test_cyclonedx_vex_parser_tolerates_empty_response_and_maps_state() -> None:
    statements = parse_cyclonedx_vex_document(
        {
            "bomFormat": "CycloneDX",
            "metadata": {"component": {"name": "repo-a"}},
            "components": [{"bom-ref": "libfoo", "name": "libfoo", "version": "1.2.3"}],
            "vulnerabilities": [
                {
                    "id": "CVE-2024-1234",
                    "analysis": {
                        "state": "resolved_with_pedigree",
                        "response": [],
                    },
                    "affects": [{"ref": "libfoo"}],
                },
                {
                    "id": "CVE-2024-5678",
                    "analysis": {"state": "exploitable", "response": ["update"]},
                    "affects": [{"ref": "libfoo"}],
                },
            ],
        }
    )

    assert [statement.status for statement in statements] == ["fixed", "affected"]
    assert statements[0].action_statement is None
    assert statements[1].action_statement == "update"


def test_vex_parsers_tolerate_null_collections_and_nested_fields() -> None:
    assert parse_openvex_document({"statements": None}) == []
    assert (
        parse_openvex_document(
            {
                "statements": [
                    {
                        "vulnerability": None,
                        "status": "not_affected",
                        "products": [{"@id": "pkg:generic/libfoo@1.2.3"}],
                    }
                ]
            }
        )
        == []
    )
    assert parse_cyclonedx_vex_document(
        {
            "metadata": None,
            "components": None,
            "vulnerabilities": [
                {
                    "id": "CVE-2024-1234",
                    "analysis": {"state": "in_triage"},
                    "affects": [{"ref": "missing-component"}],
                }
            ],
        }
    ) == [
        VexStatement(
            source_format="cyclonedx-vex-json",
            cve_id="CVE-2024-1234",
            status="under_investigation",
            target_kind="repository",
            source_record_id="vulnerability:1",
        )
    ]


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


def test_vex_matching_canonicalizes_purls_and_component_names() -> None:
    occurrence = _occurrence().model_copy(
        update={
            "component_name": " Django ",
            "component_version": "4.2.0",
            "purl": "pkg:pypi/Django@4.2.0?repository_url=https%3A%2F%2Fpypi.org",
            "target_ref": None,
        }
    )
    statements = [
        _statement(status="fixed", purl="pkg:pypi/django@4.2.0"),
        _statement(
            status="not_affected",
            component_name="django",
            component_version="4.2.0",
        ),
    ]

    match = match_vex_statement_details(occurrence, statements)

    assert match is not None
    assert match.specificity == "purl"
    assert match.statement.status == "fixed"
    assert match.candidate_count == 2


def test_vex_matching_keeps_identity_qualifiers_distinct() -> None:
    occurrence = _occurrence().model_copy(
        update={
            "purl": "pkg:deb/debian/openssl@3.0.0?distro=debian-12",
            "target_ref": None,
        }
    )
    statements = [
        _statement(
            status="not_affected",
            purl="pkg:deb/debian/openssl@3.0.0?distro=debian-11",
        ),
        _statement(
            status="fixed",
            purl="pkg:deb/debian/openssl@3.0.0?repository_url=https%3A%2F%2Fdeb.debian.org&distro=debian-12",
        ),
    ]

    match = match_vex_statement_details(occurrence, statements)

    assert match is not None
    assert match.specificity == "purl"
    assert match.statement.status == "fixed"
    assert match.candidate_count == 1


def test_openvex_subcomponent_id_is_available_for_purl_matching() -> None:
    statements = parse_openvex_document(
        {
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2024-1234"},
                    "status": "not_affected",
                    "products": [
                        {
                            "@id": "pkg:oci/acme/app@sha256:abc",
                            "subcomponents": [
                                {
                                    "@id": (
                                        "pkg:pypi/Django@4.2.0?"
                                        "repository_url=https%3A%2F%2Fpypi.org"
                                    )
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    )
    occurrence = _occurrence().model_copy(
        update={
            "component_name": "django",
            "component_version": "4.2.0",
            "purl": "pkg:pypi/django@4.2.0",
            "target_ref": None,
        }
    )

    match = match_vex_statement_details(occurrence, statements)

    assert match is not None
    assert match.specificity == "purl"
    assert match.statement.status == "not_affected"
