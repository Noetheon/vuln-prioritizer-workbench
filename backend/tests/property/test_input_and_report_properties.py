from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from utils.property_profiles import property_settings

from app.domain.engine.inputs.parsers.simple import (
    parse_cve_list,
    parse_generic_occurrence_csv,
)
from app.domain.engine.utils import normalize_cve_id

PROPERTY_SETTINGS = settings(
    parent=property_settings(),
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
        "cve_id,target_ref,component_name,component_version,fix_versions,severity",
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
