from __future__ import annotations

import importlib
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from _input_fixture_contracts import PROJECT_ROOT, load_input_fixture_contracts  # noqa: E402

_INPUT_CONTRACTS = load_input_fixture_contracts()["inputs"]
_VEX_CONTRACTS = load_input_fixture_contracts()["vex_documents"]
_OCCURRENCE_FIELDS = (
    "cve_id",
    "source_format",
    "component_name",
    "component_version",
    "purl",
    "package_type",
    "file_path",
    "dependency_path",
    "fix_versions",
    "raw_severity",
)


def _read_field(value: object, field_name: str) -> object:
    if isinstance(value, Mapping):
        return value.get(field_name)
    return getattr(value, field_name)


def _normalize_unique_cves(values: object) -> list[str]:
    result: list[str] = []
    for item in values or []:
        if isinstance(item, str):
            result.append(item)
            continue
        result.append(_read_field(item, "cve_id"))
    return result


def _project_occurrence(occurrence: object) -> dict[str, object]:
    projected = {
        field_name: _read_field(occurrence, field_name) for field_name in _OCCURRENCE_FIELDS
    }
    projected["fix_versions"] = list(projected["fix_versions"] or [])
    return projected


def _load_loader_module():
    if importlib.util.find_spec("vuln_prioritizer.inputs.loader") is None:
        pytest.skip("Future InputLoader is not implemented yet.")
    return importlib.import_module("vuln_prioritizer.inputs.loader")


@pytest.mark.parametrize(("format_name", "contract"), list(_INPUT_CONTRACTS.items()))
def test_future_input_loader_matches_contracts(format_name: str, contract: dict) -> None:
    loader_module = _load_loader_module()
    input_loader_cls = getattr(loader_module, "InputLoader", None)
    if input_loader_cls is None:
        pytest.skip("Future InputLoader class is not implemented yet.")

    loader = input_loader_cls()
    parsed = loader.load(
        path=PROJECT_ROOT / Path(contract["fixture"]),
        input_format=format_name,
    )

    assert _read_field(parsed, "total_rows") == contract["expected_total_rows"]
    assert len(_read_field(parsed, "occurrences")) == contract["expected_occurrence_count"]
    assert (
        _normalize_unique_cves(_read_field(parsed, "unique_cves"))
        == contract["expected_unique_cves"]
    )

    projected_occurrences = [
        _project_occurrence(item) for item in _read_field(parsed, "occurrences")
    ]
    assert projected_occurrences == contract["expected_occurrences"]


@pytest.mark.parametrize(("format_name", "contract"), list(_VEX_CONTRACTS.items()))
def test_future_vex_loader_matches_contracts(format_name: str, contract: dict) -> None:
    loader_module = _load_loader_module()
    load_vex_files = getattr(loader_module, "load_vex_files", None)
    if load_vex_files is None:
        pytest.skip("Future load_vex_files helper is not implemented yet.")

    statements = load_vex_files([PROJECT_ROOT / Path(contract["fixture"])])
    projected = [
        {
            "cve_id": _read_field(statement, "cve_id"),
            "product_id": _read_field(statement, "purl"),
            "status": _read_field(statement, "status"),
        }
        for statement in statements
    ]
    statuses = sorted({_read_field(statement, "status") for statement in statements})

    assert statuses == contract["expected_statuses"]
    assert projected == contract["expected_matches"]


@pytest.mark.parametrize(
    ("format_name", "expected_identifier"),
    [
        ("nessus-xml", "GHSA-4mx6-2q88-pq62"),
        ("openvas-xml", "GHSA-9m7r-4c2v-9j5j"),
    ],
)
def test_xml_input_loader_preserves_non_cve_warnings(
    format_name: str,
    expected_identifier: str,
) -> None:
    loader_module = _load_loader_module()
    input_loader_cls = getattr(loader_module, "InputLoader", None)
    if input_loader_cls is None:
        pytest.skip("Future InputLoader class is not implemented yet.")

    loader = input_loader_cls()
    parsed = loader.load(
        path=PROJECT_ROOT / Path(_INPUT_CONTRACTS[format_name]["fixture"]),
        input_format=format_name,
    )

    assert expected_identifier in "\n".join(_read_field(parsed, "warnings"))


def test_detect_input_format_rejects_xml_doctype_and_entity_declarations(tmp_path: Path) -> None:
    loader_module = _load_loader_module()
    detect_input_format = getattr(loader_module, "detect_input_format", None)
    if detect_input_format is None:
        pytest.skip("Future detect_input_format helper is not implemented yet.")

    xml_file = tmp_path / "unsafe.xml"
    xml_file.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE report [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<report/>""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="DOCTYPE or ENTITY declaration"):
        detect_input_format(xml_file)


def test_input_loader_rejects_invalid_xml_with_explicit_format(tmp_path: Path) -> None:
    loader_module = _load_loader_module()
    input_loader_cls = getattr(loader_module, "InputLoader", None)
    if input_loader_cls is None:
        pytest.skip("Future InputLoader class is not implemented yet.")

    xml_file = tmp_path / "broken.nessus"
    xml_file.write_text("<NessusClientData_v2><Report>", encoding="utf-8")

    loader = input_loader_cls()
    with pytest.raises(ValueError, match="XML input is not valid XML"):
        loader.load(path=xml_file, input_format="nessus-xml")
