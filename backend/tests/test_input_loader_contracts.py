from __future__ import annotations

import importlib
import json
from collections.abc import Mapping
from pathlib import Path

import pytest
from _input_fixture_contracts import PROJECT_ROOT, load_input_fixture_contracts

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
    return importlib.import_module("app.domain.engine.inputs.loader")


@pytest.mark.parametrize(("format_name", "contract"), list(_INPUT_CONTRACTS.items()))
def test_input_loader_matches_contracts(format_name: str, contract: dict) -> None:
    loader_module = _load_loader_module()
    loader = loader_module.InputLoader()
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
def test_vex_loader_matches_contracts(format_name: str, contract: dict) -> None:
    loader_module = _load_loader_module()
    statements = loader_module.load_vex_files([PROJECT_ROOT / Path(contract["fixture"])])
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
    loader = loader_module.InputLoader()
    parsed = loader.load(
        path=PROJECT_ROOT / Path(_INPUT_CONTRACTS[format_name]["fixture"]),
        input_format=format_name,
    )

    assert expected_identifier in "\n".join(_read_field(parsed, "warnings"))


def test_detect_input_format_rejects_xml_doctype_and_entity_declarations(tmp_path: Path) -> None:
    loader_module = _load_loader_module()

    xml_file = tmp_path / "unsafe.xml"
    xml_file.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE report [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<report/>""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="DOCTYPE or ENTITY declaration"):
        loader_module.detect_input_format(xml_file)


def test_input_loader_rejects_invalid_xml_with_explicit_format(tmp_path: Path) -> None:
    loader_module = _load_loader_module()

    xml_file = tmp_path / "broken.nessus"
    xml_file.write_text("<NessusClientData_v2><Report>", encoding="utf-8")

    loader = loader_module.InputLoader()
    with pytest.raises(ValueError, match="XML input is not valid XML") as exc_info:
        loader.load(path=xml_file, input_format="nessus-xml")
    assert str(tmp_path) not in str(exc_info.value)


def test_json_parser_rejects_wrong_top_level_type_before_parser_access(tmp_path: Path) -> None:
    loader_module = _load_loader_module()
    input_file = tmp_path / "trivy.json"
    input_file.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="Trivy JSON must be a top-level JSON object"):
        loader_module.InputLoader().load(input_file, input_format="trivy-json")


def test_clean_scanner_reports_name_examined_targets_only_when_allowed(tmp_path: Path) -> None:
    loader = _load_loader_module().InputLoader()
    trivy = tmp_path / "trivy.json"
    trivy.write_text(
        json.dumps(
            {
                "ArtifactName": "app:2.0",
                "ArtifactType": "container_image",
                "Results": [
                    {"Target": "app:2.0 (debian 12.6)", "Type": "debian"},
                    {"Target": "app:2.0 (debian 12.6)", "Type": "debian"},
                    {"Type": "jar"},
                ],
            }
        ),
        encoding="utf-8",
    )
    grype = tmp_path / "grype.json"
    grype.write_text(
        json.dumps({"matches": [], "source": {"type": "image", "target": {"name": "alpine"}}}),
        encoding="utf-8",
    )
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps({"Results": []}), encoding="utf-8")

    with pytest.raises(ValueError, match="No valid CVE identifiers"):
        loader.load(trivy, input_format="trivy-json")
    with pytest.raises(ValueError, match="No valid CVE identifiers"):
        loader.load(bare, input_format="trivy-json", allow_empty_examined=True)

    parsed = loader.load(trivy, input_format="trivy-json", allow_empty_examined=True)
    assert parsed.unique_cves == []
    assert [(item.target_kind, item.target_ref) for item in parsed.examined_targets] == [
        ("image", "app:2.0 (debian 12.6)"),
        ("image", "app:2.0"),
    ]
    grype_parsed = loader.load(grype, input_format="grype-json", allow_empty_examined=True)
    assert [
        (item.source_format, item.target_kind, item.target_ref)
        for item in grype_parsed.examined_targets
    ] == [("grype-json", "image", "alpine")]


def test_advisories_without_cves_are_summarized_before_details(tmp_path: Path) -> None:
    from app.domain.engine.inputs._cve_support import summarize_non_cve_identifiers

    trivy = tmp_path / "trivy.json"
    trivy.write_text(
        json.dumps(
            {
                "ArtifactName": "app:3",
                "Results": [
                    {
                        "Target": "go.sum",
                        "Vulnerabilities": [
                            {"VulnerabilityID": "GO-2026-0001"},
                            {"VulnerabilityID": "GHSA-aaaa-bbbb-cccc"},
                            {"VulnerabilityID": "GO-2026-0001"},
                            {"VulnerabilityID": "CVE-2026-0101"},
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    parsed = _load_loader_module().InputLoader().load(trivy, input_format="trivy-json")

    assert parsed.unique_cves == ["CVE-2026-0101"]
    assert parsed.warnings[0] == (
        "Not imported: 2 vulnerabilities without a CVE identifier "
        "(GO-2026-0001, GHSA-aaaa-bbbb-cccc). The Workbench prioritizes "
        "CVE-identified findings; review these in the source report."
    )
    assert "Ignored non-CVE Trivy vulnerability identifier: 'GO-2026-0001'" in parsed.warnings
    assert summarize_non_cve_identifiers(parsed.warnings) == parsed.warnings
    assert summarize_non_cve_identifiers(["Unrelated warning"]) == ["Unrelated warning"]
    many = [f"Ignored non-CVE Grype vulnerability identifier: 'GHSA-{i}'" for i in range(7)]
    assert "GHSA-4, +2 more" in summarize_non_cve_identifiers(many)[0]
    single = ["Ignored non-CVE Nessus identifier in host-1: 'MS17-010'"]
    assert summarize_non_cve_identifiers(single)[0].startswith(
        "Not imported: 1 vulnerability without a CVE identifier (MS17-010)"
    )


def test_dependency_check_empty_project_references_are_ignored(tmp_path: Path) -> None:
    loader_module = _load_loader_module()
    input_file = tmp_path / "dependency-check.json"
    input_file.write_text(
        """{
  "scanInfo": {},
  "dependencies": [
    {
      "fileName": "app.jar",
      "projectReferences": [],
      "vulnerabilities": [{"name": "CVE-2024-0001", "severity": "HIGH"}]
    }
  ]
}""",
        encoding="utf-8",
    )

    parsed = loader_module.InputLoader().load(
        input_file,
        input_format="dependency-check-json",
    )

    assert parsed.occurrences[0].target_ref is None
    assert parsed.unique_cves == ["CVE-2024-0001"]


def test_generic_occurrence_csv_preserves_component_target_and_asset_context(
    tmp_path: Path,
) -> None:
    loader_module = _load_loader_module()
    input_file = tmp_path / "generic-occurrences.csv"
    input_file.write_text(
        "\n".join(
            [
                ",".join(
                    [
                        "cve_id",
                        "component_name",
                        "component_version",
                        "purl",
                        "fix_versions",
                        "target_ref",
                        "criticality",
                        "exposure",
                        "environment",
                        "owner",
                        "business_service",
                        "raw_severity",
                    ]
                ),
                ",".join(
                    [
                        "CVE-2024-0001",
                        "Django",
                        "4.2.0",
                        "pkg:pypi/django@4.2.0",
                        "4.2.8",
                        "backend/requirements.txt",
                        "Crit",
                        "public",
                        "production",
                        "team-app",
                        "identity",
                        "HIGH",
                    ]
                ),
                ",".join(["not-a-cve", "ignored", "", "", "", "", "", "", "", "", "", ""]),
                ",".join(
                    [
                        "CVE-2024-0002",
                        "openssl",
                        "3.0.0",
                        "",
                        "3.0.13",
                        "app-01",
                        "urgent",
                        "edge",
                        "live",
                        "team-platform",
                        "payments",
                        "critical",
                    ]
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    parsed = loader_module.InputLoader().load(input_file)

    assert parsed.total_rows == 3
    assert parsed.input_format == "generic-occurrence-csv"
    assert parsed.unique_cves == ["CVE-2024-0001", "CVE-2024-0002"]
    first, second = parsed.occurrences
    assert first.source_format == "generic-occurrence-csv"
    assert first.component_name == "Django"
    assert first.component_version == "4.2.0"
    assert first.purl == "pkg:pypi/django@4.2.0"
    assert first.fix_versions == ["4.2.8"]
    assert first.target_kind == "generic"
    assert first.target_ref == "backend/requirements.txt"
    assert first.asset_id is None
    assert first.asset_criticality == "critical"
    assert first.asset_exposure == "internet-facing"
    assert first.asset_environment == "prod"
    assert first.asset_owner == "team-app"
    assert first.asset_business_service == "identity"
    assert first.raw_severity == "HIGH"
    assert second.asset_criticality is None
    assert second.asset_exposure is None
    assert second.asset_environment is None
    assert any("Ignored invalid CVE identifier" in warning for warning in parsed.warnings)
    assert any("unknown asset criticality" in warning for warning in parsed.warnings)
    assert any("unknown asset exposure" in warning for warning in parsed.warnings)
    assert any("unknown asset environment" in warning for warning in parsed.warnings)


def test_generic_occurrence_csv_auto_detection_sniffs_delimiters_and_comments(
    tmp_path: Path,
) -> None:
    loader_module = _load_loader_module()
    input_file = tmp_path / "generic-occurrences.csv"
    input_file.write_text(
        "\n".join(
            [
                "# exported from scanner",
                "cve_id;component_name;component_version;target_ref",
                "CVE-2024-0101;openssl;3.0.0;host-01",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert loader_module.detect_input_format(input_file) == "generic-occurrence-csv"
    parsed = loader_module.InputLoader().load(input_file)

    assert parsed.input_format == "generic-occurrence-csv"
    assert parsed.unique_cves == ["CVE-2024-0101"]
    assert parsed.occurrences[0].component_name == "openssl"


def test_generic_occurrence_csv_sniffs_semicolon_dialect_and_warns_unknowns(
    tmp_path: Path,
) -> None:
    loader_module = _load_loader_module()
    input_file = tmp_path / "generic.csv"
    input_file.write_text(
        "\n".join(
            [
                "# comment before header",
                "cve_id;target_ref;component_name;component_version;source;ticket_url",
                "CVE-2024-3094;build-host-1;xz;5.6.0;trivy;SEC-1001",
            ]
        ),
        encoding="utf-8",
    )

    parsed = loader_module.InputLoader().load(
        input_file,
        input_format="generic-occurrence-csv",
    )

    assert parsed.unique_cves == ["CVE-2024-3094"]
    assert parsed.occurrences[0].target_ref == "build-host-1"
    assert any("ticket_url" in warning for warning in parsed.warnings)


def test_generic_occurrence_csv_accepts_quoted_multiline_values(tmp_path: Path) -> None:
    loader_module = _load_loader_module()
    input_file = tmp_path / "generic.csv"
    input_file.write_text(
        "cve_id,target_ref,component_name,notes\n"
        'CVE-2024-3094,build-host-1,xz,"line one\nline two"\n',
        encoding="utf-8",
    )

    parsed = loader_module.InputLoader().load(
        input_file,
        input_format="generic-occurrence-csv",
    )

    assert parsed.unique_cves == ["CVE-2024-3094"]
    assert parsed.occurrences[0].target_ref == "build-host-1"
    assert parsed.occurrences[0].source_record_id == "row:2"
    assert any("notes" in warning for warning in parsed.warnings)


def test_plain_cve_csv_auto_detects_as_cve_list(tmp_path: Path) -> None:
    loader_module = _load_loader_module()
    input_file = tmp_path / "cves.csv"
    input_file.write_text("cve_id\nCVE-2024-0001\n", encoding="utf-8")

    parsed = loader_module.InputLoader().load(input_file)

    assert parsed.input_format == "cve-list"
    assert parsed.unique_cves == ["CVE-2024-0001"]


def test_plain_cve_list_preserves_minimal_csv_context_and_deduplicates(tmp_path: Path) -> None:
    loader_module = _load_loader_module()
    input_file = tmp_path / "cves.csv"
    input_file.write_text(
        "\n".join(
            [
                "# comment before header",
                "cve_id,target_ref,component_name,component_version",
                "CVE-2024-3094,build-host-1,xz,5.6.0",
                "cve-2024-3094,build-host-1,xz,5.6.0",
                "CVE-2024-4577,web-tier,php,8.3.7",
            ]
        ),
        encoding="utf-8",
    )

    parsed = loader_module.InputLoader().load(input_file, input_format="cve-list")

    assert parsed.unique_cves == ["CVE-2024-3094", "CVE-2024-4577"]
    assert len(parsed.occurrences) == 2
    first = parsed.occurrences[0]
    assert first.component_name == "xz"
    assert first.component_version == "5.6.0"
    assert first.target_ref == "build-host-1"


def test_plain_cve_txt_skips_comment_lines(tmp_path: Path) -> None:
    loader_module = _load_loader_module()
    input_file = tmp_path / "cves.txt"
    input_file.write_text("# comment\n\nCVE-2024-3094\n", encoding="utf-8")

    parsed = loader_module.InputLoader().load(input_file, input_format="cve-list")

    assert parsed.unique_cves == ["CVE-2024-3094"]
    assert parsed.total_rows == 1


def test_github_alerts_skips_non_object_items(tmp_path: Path) -> None:
    loader_module = _load_loader_module()
    input_file = tmp_path / "alerts.json"
    input_file.write_text(
        """[
  "not-an-alert-object",
  {
    "number": 7,
    "security_advisory": {
      "cve_id": "CVE-2024-0002",
      "severity": "high",
      "identifiers": []
    },
    "dependency": {
      "package": {"name": "pkg", "ecosystem": "npm"},
      "manifest_path": "package-lock.json"
    }
  }
]""",
        encoding="utf-8",
    )

    parsed = loader_module.InputLoader().load(
        input_file,
        input_format="github-alerts-json",
    )

    assert parsed.total_rows == 2
    assert parsed.unique_cves == ["CVE-2024-0002"]
    assert any("not JSON objects" in warning for warning in parsed.warnings)


def test_vex_loader_rejects_wrong_statement_container_type(tmp_path: Path) -> None:
    loader_module = _load_loader_module()
    vex_file = tmp_path / "openvex.json"
    vex_file.write_text('{"statements": {}}', encoding="utf-8")

    with pytest.raises(ValueError, match="OpenVEX JSON `statements`"):
        loader_module.load_vex_files([vex_file])


def test_vex_loader_rejects_wrong_cyclonedx_vulnerabilities_container(
    tmp_path: Path,
) -> None:
    loader_module = _load_loader_module()
    vex_file = tmp_path / "cyclonedx-vex.json"
    vex_file.write_text(
        '{"bomFormat": "CycloneDX", "vulnerabilities": {}}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="CycloneDX VEX JSON `vulnerabilities`"):
        loader_module.load_vex_files([vex_file])


def test_vex_loader_reports_cyclonedx_statement_skip_reasons(tmp_path: Path) -> None:
    loader_module = _load_loader_module()
    vex_file = tmp_path / "cyclonedx-vex.json"
    vex_file.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [],
                "vulnerabilities": [
                    {
                        "id": "CVE-2024-1234",
                        "analysis": {"state": "resolved"},
                        "affects": [{"ref": "missing-component"}],
                    },
                    {
                        "id": "CVE-2024-5678",
                        "analysis": {"state": "unknown-state"},
                        "affects": [{"ref": "pkg:generic/libfoo@1.2.3"}],
                    },
                    {
                        "id": "CVE-2024-9999",
                        "analysis": {"state": "in_triage"},
                        "affects": {},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    statements, diagnostics = loader_module.load_vex_files(
        [vex_file],
        return_diagnostics=True,
    )

    assert statements == []
    assert diagnostics.skipped_statements == 3
    warning_text = "\n".join(diagnostics.warnings)
    assert "unresolved bom-ref 'missing-component'" in warning_text
    assert "unsupported analysis.state 'unknown-state'" in warning_text
    assert "affects must be a list" in warning_text


def test_vex_loader_rejects_malformed_json_and_non_object_roots(tmp_path: Path) -> None:
    loader_module = _load_loader_module()
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    non_object = tmp_path / "array.json"
    non_object.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="VEX JSON parsing failed"):
        loader_module.load_vex_files([malformed])
    with pytest.raises(ValueError, match="VEX JSON root"):
        loader_module.load_vex_files([non_object])
