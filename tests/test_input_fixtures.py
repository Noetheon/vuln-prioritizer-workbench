from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from _input_fixture_contracts import PROJECT_ROOT, load_input_fixture_contracts  # noqa: E402

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")
_GHSA_PATTERN = re.compile(r"GHSA-[a-z0-9-]+", re.IGNORECASE)

_CONTRACTS = load_input_fixture_contracts()
_INPUT_CONTRACTS = _CONTRACTS["inputs"]
_VEX_CONTRACTS = _CONTRACTS["vex_documents"]


def _collect_strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, list):
        for item in value:
            yield from _collect_strings(item)
        return
    if isinstance(value, dict):
        for item in value.values():
            yield from _collect_strings(item)


def _xml_local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", maxsplit=1)[1]
    return tag


def _collect_xml_strings(element: ET.Element) -> Iterable[str]:
    yield _xml_local_name(element.tag)
    for key, value in element.attrib.items():
        yield key
        yield value
    if element.text and element.text.strip():
        yield element.text.strip()
    for child in element:
        yield from _collect_xml_strings(child)


def _load_fixture_payload(contract: dict) -> object:
    fixture_path = PROJECT_ROOT / Path(contract["fixture"])
    fixture_format = contract.get("fixture_format", "json")
    if fixture_format == "xml":
        return ET.fromstring(fixture_path.read_bytes())
    return json.loads(fixture_path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("format_name", "contract"),
    list(_INPUT_CONTRACTS.items()) + list(_VEX_CONTRACTS.items()),
)
def test_fixture_files_exist_and_parse(format_name: str, contract: dict) -> None:
    fixture_path = PROJECT_ROOT / Path(contract["fixture"])
    assert fixture_path.is_file(), f"Missing fixture for {format_name}: {fixture_path}"
    payload = _load_fixture_payload(contract)
    if contract["top_level_kind"] == "object":
        assert isinstance(payload, dict)
    elif contract["top_level_kind"] == "list":
        assert isinstance(payload, list)
    else:
        assert isinstance(payload, ET.Element)


@pytest.mark.parametrize(("format_name", "contract"), list(_INPUT_CONTRACTS.items()))
def test_input_fixture_contracts_are_internally_consistent(
    format_name: str,
    contract: dict,
) -> None:
    expected_occurrences = contract["expected_occurrences"]
    expected_unique_cves = contract["expected_unique_cves"]
    deduped_occurrence_order: list[str] = []
    seen: set[str] = set()
    for item in expected_occurrences:
        cve_id = item["cve_id"]
        if cve_id in seen:
            continue
        seen.add(cve_id)
        deduped_occurrence_order.append(cve_id)

    assert contract["expected_occurrence_count"] == len(expected_occurrences)
    assert len(expected_unique_cves) == len(set(expected_unique_cves)), format_name
    assert deduped_occurrence_order == expected_unique_cves, format_name
    assert contract["expected_total_rows"] >= contract["expected_occurrence_count"]


@pytest.mark.parametrize(("format_name", "contract"), list(_INPUT_CONTRACTS.items()))
def test_input_fixtures_expose_expected_ids_and_shape(
    format_name: str,
    contract: dict,
) -> None:
    payload = _load_fixture_payload(contract)

    if contract["top_level_kind"] == "object":
        assert set(contract["raw_top_level_keys"]).issubset(payload)
        strings = list(_collect_strings(payload))
    elif contract["top_level_kind"] == "list":
        assert payload, f"{format_name} fixture must not be empty"
        assert set(contract["raw_item_keys"]).issubset(payload[0])
        strings = list(_collect_strings(payload))
    else:
        assert _xml_local_name(payload.tag) == contract["raw_top_level_tag"]
        assert set(contract["raw_top_level_keys"]).issubset(
            {_xml_local_name(child.tag) for child in payload}
        )
        strings = list(_collect_xml_strings(payload))

    cve_ids = sorted({match.upper() for value in strings for match in _CVE_PATTERN.findall(value)})
    advisory_ids = sorted(
        {match.upper() for value in strings for match in _GHSA_PATTERN.findall(value)}
    )
    expected_non_cve_ids = {item.upper() for item in contract["expected_non_cve_ids"]}

    assert set(contract["expected_unique_cves"]).issubset(cve_ids), format_name
    assert expected_non_cve_ids.issubset(advisory_ids), format_name


@pytest.mark.parametrize(("format_name", "contract"), list(_VEX_CONTRACTS.items()))
def test_vex_fixtures_expose_expected_statuses_and_matches(
    format_name: str,
    contract: dict,
) -> None:
    fixture_path = PROJECT_ROOT / Path(contract["fixture"])
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))

    assert set(contract["raw_top_level_keys"]).issubset(payload)

    if format_name == "openvex-json":
        statuses = sorted({statement["status"] for statement in payload["statements"]})
        matches = [
            {
                "cve_id": statement["vulnerability"]["name"],
                "product_id": statement["products"][0]["@id"],
                "status": statement["status"],
            }
            for statement in payload["statements"]
        ]
    else:
        statuses = sorted({item["analysis"]["state"] for item in payload["vulnerabilities"]})
        matches = [
            {
                "cve_id": item["id"],
                "product_id": item["affects"][0]["ref"],
                "status": item["analysis"]["state"],
            }
            for item in payload["vulnerabilities"]
        ]

    assert statuses == contract["expected_statuses"]
    assert matches == contract["expected_matches"]
