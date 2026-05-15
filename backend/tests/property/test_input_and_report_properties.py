from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.services.report_bundle_archive_verification import (
    describe_evidence_bundle_mismatch,
    validate_evidence_manifest_structure,
)
from app.services.report_sarif_validation import validate_sarif_payload
from vuln_prioritizer.inputs.parsers.simple import (
    parse_cve_list,
    parse_generic_occurrence_csv,
)
from vuln_prioritizer.models import EvidenceBundleFile, EvidenceBundleManifest
from vuln_prioritizer.utils import normalize_cve_id

PROPERTY_SETTINGS = settings(
    deadline=None,
    derandomize=True,
    max_examples=40,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


def cve_ids() -> st.SearchStrategy[str]:
    year = st.integers(min_value=1999, max_value=2099)
    sequence = st.integers(min_value=0, max_value=9_999_999).map(lambda value: f"{value:04d}")
    return st.builds(
        lambda generated_year, suffix: f"CVE-{generated_year}-{suffix}", year, sequence
    )


@pytest.mark.property
@PROPERTY_SETTINGS
@given(cve_id=cve_ids())
def test_cve_normalization_is_idempotent(cve_id: str) -> None:
    normalized = normalize_cve_id(f"  {cve_id.lower()}  ")

    assert normalized == cve_id
    assert normalize_cve_id(normalized) == normalized


@pytest.mark.property
@PROPERTY_SETTINGS
@given(raw_cves=st.lists(cve_ids(), min_size=1, max_size=12, unique=True))
def test_simple_cve_list_parser_accepts_generated_valid_inputs(
    tmp_path: Path,
    raw_cves: list[str],
) -> None:
    input_path = tmp_path / "cves.txt"
    input_path.write_text(
        "\n".join(f"  {cve_id.lower()}  " for cve_id in raw_cves),
        encoding="utf-8",
    )

    parsed = parse_cve_list(input_path)

    assert [occurrence.cve_id for occurrence in parsed.occurrences] == raw_cves
    assert parsed.warnings == []


@pytest.mark.property
@PROPERTY_SETTINGS
@given(raw_cves=st.lists(cve_ids(), min_size=1, max_size=12, unique=True))
def test_generic_occurrence_parser_accepts_generated_valid_csv(
    tmp_path: Path,
    raw_cves: list[str],
) -> None:
    input_path = tmp_path / "occurrences.csv"
    rows = [
        "cve_id,asset_ref,component,version,fix_versions,severity",
        *(
            f"{cve_id},asset-{index},component-{index},1.{index}.0,2.{index}.0|2.{index}.1,HIGH"
            for index, cve_id in enumerate(raw_cves, start=1)
        ),
    ]
    input_path.write_text("\n".join(rows), encoding="utf-8")

    parsed = parse_generic_occurrence_csv(input_path)

    assert [occurrence.cve_id for occurrence in parsed.occurrences] == raw_cves
    assert parsed.total_rows == len(raw_cves)
    assert all(occurrence.fix_versions for occurrence in parsed.occurrences)


@pytest.mark.property
@PROPERTY_SETTINGS
@given(
    header=st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
        min_size=1,
        max_size=16,
    ).filter(lambda value: value.strip().lower() not in {"cve", "cve_id", "vulnerability_id"})
)
def test_generic_occurrence_parser_rejects_structurally_invalid_csv(
    tmp_path: Path,
    header: str,
) -> None:
    input_path = tmp_path / "invalid.csv"
    input_path.write_text(f"{header}\nCVE-2024-3094\n", encoding="utf-8")

    with pytest.raises(ValueError, match="must contain"):
        parse_generic_occurrence_csv(input_path)


json_scalar = st.one_of(st.none(), st.booleans(), st.integers(-10, 10), st.text(max_size=16))
json_values: st.SearchStrategy[Any] = st.recursive(
    json_scalar,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=16), children, max_size=4),
    ),
    max_leaves=12,
)


@pytest.mark.property
@PROPERTY_SETTINGS
@given(payload=st.dictionaries(st.text(max_size=16), json_values, max_size=6))
def test_sarif_validator_is_deterministic_for_generated_payloads(
    payload: dict[str, Any],
) -> None:
    first_errors = validate_sarif_payload(payload)
    second_errors = validate_sarif_payload(payload)

    assert first_errors == second_errors
    assert all(isinstance(error, str) and error for error in first_errors)


bundle_paths = st.lists(
    st.sampled_from(
        [
            "analysis-result.v1.json",
            "findings.csv",
            "manifest.json",
            "reports/technical-report.md",
        ]
    ),
    min_size=0,
    max_size=8,
)


@pytest.mark.property
@PROPERTY_SETTINGS
@given(paths=bundle_paths, size=st.integers(min_value=0, max_value=1024))
def test_evidence_manifest_validator_is_deterministic_for_generated_paths(
    paths: list[str],
    size: int,
) -> None:
    digest = hashlib.sha256(str(size).encode()).hexdigest()
    manifest = EvidenceBundleManifest(
        generated_at="2026-05-15T00:00:00Z",
        source_analysis_path="analysis-result.v1.json",
        files=[
            EvidenceBundleFile(
                path=path,
                kind="generated",
                size_bytes=size,
                sha256=digest,
            )
            for path in paths
        ],
    )

    first_errors = validate_evidence_manifest_structure(manifest)
    second_errors = validate_evidence_manifest_structure(manifest)

    assert [(item.path, item.detail) for item in first_errors] == [
        (item.path, item.detail) for item in second_errors
    ]


@pytest.mark.property
@PROPERTY_SETTINGS
@given(actual_size=st.integers(min_value=0, max_value=2048), content=st.binary(max_size=32))
def test_evidence_bundle_mismatch_description_is_deterministic(
    actual_size: int,
    content: bytes,
) -> None:
    expected = EvidenceBundleFile(
        path="analysis-result.v1.json",
        kind="analysis-json",
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )
    actual_sha256 = hashlib.sha256(content + b"x").hexdigest()

    assert describe_evidence_bundle_mismatch(
        expected=expected,
        actual_size=actual_size,
        actual_sha256=actual_sha256,
    ) == describe_evidence_bundle_mismatch(
        expected=expected,
        actual_size=actual_size,
        actual_sha256=actual_sha256,
    )
