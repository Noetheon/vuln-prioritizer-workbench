from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from xml.etree.ElementTree import Element, fromstring

import pytest

from app.domain.engine.inputs import _xml_support as xml_support
from app.domain.engine.inputs._occurrence_support import (
    _asset_context_rule_matches,
    apply_asset_context,
    finalize_occurrences,
)
from app.domain.engine.inputs.loader import detect_input_format
from app.domain.engine.inputs.parsers.sbom import parse_cyclonedx_json, parse_spdx_json
from app.domain.engine.models import AssetContextRecord, InputOccurrence, InputSourceSummary


def _occurrence(target_ref: str | None, *, cve_id: str = "CVE-2024-0001") -> InputOccurrence:
    return InputOccurrence(
        cve_id=cve_id,
        source_format="unit",
        target_kind="host",
        target_ref=target_ref,
    )


def _rule(
    *,
    rule_id: str,
    target_ref: str,
    match_mode: str,
    asset_id: str,
    precedence: int = 10,
    order: int = 0,
) -> SimpleNamespace:
    return SimpleNamespace(
        target_kind="host",
        target_ref=target_ref,
        match_mode=match_mode,
        precedence=precedence,
        order=order,
        asset_record=AssetContextRecord(
            target_kind="host",
            target_ref=target_ref,
            asset_id=asset_id,
            rule_id=rule_id,
            match_mode=match_mode,
            precedence=precedence,
            row_number=order + 1,
        ),
    )


def test_asset_context_rule_mode_diagnostics_cover_glob_and_regex() -> None:
    catalog = SimpleNamespace(
        rules=[
            _rule(rule_id="glob-web", target_ref="web-*", match_mode="glob", asset_id="web"),
            _rule(
                rule_id="regex-db",
                target_ref=r"^db-\d+$",
                match_mode="regex",
                asset_id="database",
            ),
        ]
    )

    enriched, diagnostics = apply_asset_context(
        [
            _occurrence("web-01", cve_id="CVE-2024-0001"),
            _occurrence("db-42", cve_id="CVE-2024-0002"),
        ],
        catalog,
        return_diagnostics=True,
    )

    assert [item.asset_id for item in enriched] == ["web", "database"]
    assert diagnostics.matched_occurrences == 2
    assert diagnostics.glob_matches == 1
    assert diagnostics.regex_matches == 1
    assert diagnostics.exact_matches == 0


def test_asset_context_exact_mapping_reports_matched_and_unmatched_occurrences() -> None:
    exact_records = {
        ("host", "app-01"): AssetContextRecord(
            target_kind="host",
            target_ref="app-01",
            asset_id="asset-app",
            criticality="high",
        )
    }

    enriched, diagnostics = apply_asset_context(
        [
            _occurrence(None, cve_id="CVE-2024-0001"),
            _occurrence("missing", cve_id="CVE-2024-0002"),
            _occurrence("app-01", cve_id="CVE-2024-0003"),
        ],
        exact_records,
        return_diagnostics=True,
    )

    assert [item.asset_id for item in enriched] == [None, None, "asset-app"]
    assert diagnostics.matched_occurrences == 1
    assert diagnostics.unmatched_occurrences == 2
    assert diagnostics.exact_matches == 1
    assert diagnostics.glob_matches == 0


def test_asset_context_rule_match_rejects_kind_mismatch_and_invalid_regex() -> None:
    occurrence = _occurrence("app-01")

    assert (
        _asset_context_rule_matches(
            occurrence,
            SimpleNamespace(target_kind="image", target_ref="app-01", match_mode="exact"),
        )
        is False
    )
    assert (
        _asset_context_rule_matches(
            occurrence,
            SimpleNamespace(target_kind="host", target_ref="[app", match_mode="regex"),
        )
        is False
    )
    assert (
        _asset_context_rule_matches(
            _occurrence("a" * 30 + "X"),
            SimpleNamespace(target_kind="host", target_ref="^(a+)+$", match_mode="regex"),
        )
        is False
    )


def test_finalize_occurrences_tracks_truncation_duplicates_and_source_summary() -> None:
    source_summary = InputSourceSummary(
        input_path="input.csv",
        input_format="unit",
        total_rows=3,
        occurrence_count=3,
        unique_cves=2,
    )

    parsed = finalize_occurrences(
        [
            InputOccurrence(cve_id="CVE-2024-0001", source_format="unit-a"),
            InputOccurrence(cve_id="CVE-2024-0001", source_format="unit-b"),
            InputOccurrence(cve_id="CVE-2024-0002", source_format="unit-b"),
        ],
        input_format="merged",
        warnings=[],
        total_rows=3,
        max_cves=1,
        input_paths=["a.csv", "b.csv"],
        source_summaries=[source_summary],
        merged_input_count=2,
        asset_match_conflict_count=1,
        vex_conflict_count=2,
    )

    assert parsed.unique_cves == ["CVE-2024-0001"]
    assert parsed.included_occurrence_count == 2
    assert parsed.included_unique_cves == 1
    assert parsed.duplicate_cve_count == 1
    assert parsed.asset_match_conflict_count == 1
    assert parsed.vex_conflict_count == 2
    assert parsed.source_summaries[0].included_occurrence_count == 2
    assert any("Applied --max-cves 1" in warning for warning in parsed.warnings)
    assert any("collapsed duplicate CVEs" in warning for warning in parsed.warnings)


def test_finalize_occurrences_rejects_empty_inputs() -> None:
    with pytest.raises(ValueError, match="No valid CVE identifiers"):
        finalize_occurrences(
            [],
            input_format="unit",
            warnings=[],
            total_rows=0,
            max_cves=None,
        )


def test_sbom_parsers_cover_repository_and_missing_package_metadata(tmp_path: Path) -> None:
    cyclonedx_file = tmp_path / "cyclonedx.json"
    cyclonedx_file.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "metadata": {"component": {"name": "checkout-repo"}},
                "vulnerabilities": [
                    {"id": "CVE-2024-3094"},
                    {"id": "CVE-2024-4577", "affects": [{"ref": "component-a"}]},
                ],
                "components": [{"bom-ref": "component-a", "name": "xz", "version": "5.6.0"}],
            }
        ),
        encoding="utf-8",
    )
    cyclonedx = parse_cyclonedx_json(cyclonedx_file)

    assert [item.source_record_id for item in cyclonedx.occurrences] == [
        "vulnerability:1",
        "vulnerability:2:affect:1",
    ]
    assert cyclonedx.occurrences[0].target_ref == "checkout-repo"
    assert cyclonedx.occurrences[0].raw_severity is None
    assert cyclonedx.occurrences[1].component_name == "xz"

    spdx_file = tmp_path / "spdx.json"
    spdx_file.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "name": "checkout-sbom",
                "packages": [{"SPDXID": "SPDXRef-xz", "name": "xz", "externalRefs": []}],
                "vulnerabilities": [
                    {"id": "CVE-2024-3094", "severity": "critical"},
                    {
                        "id": "CVE-2024-4577",
                        "severity": "high",
                        "affects": [{"ref": "SPDXRef-xz"}],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    spdx = parse_spdx_json(spdx_file)

    assert [item.source_record_id for item in spdx.occurrences] == [
        "vulnerability:1",
        "vulnerability:2:affect:1",
    ]
    assert spdx.occurrences[0].target_ref == "checkout-sbom"
    assert spdx.occurrences[1].purl is None
    assert spdx.occurrences[1].component_name == "xz"


def test_xml_root_rejects_doctype_defused_errors_and_parse_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    doctype_path = tmp_path / "doctype.xml"
    doctype_path.write_text("<!DOCTYPE root><root />", encoding="utf-8")
    with pytest.raises(ValueError, match="DOCTYPE or ENTITY"):
        xml_support.load_xml_root(doctype_path)

    blocked_path = tmp_path / "blocked.xml"
    blocked_path.write_text("<root />", encoding="utf-8")

    def blocked_fromstring(_raw: bytes) -> Element:
        raise xml_support.DefusedXmlException("blocked")

    monkeypatch.setattr(xml_support.DefusedET, "fromstring", blocked_fromstring)
    with pytest.raises(ValueError, match="unsupported XML declarations"):
        xml_support.load_xml_root(blocked_path)

    monkeypatch.undo()
    malformed_path = tmp_path / "malformed.xml"
    malformed_path.write_text("<root>", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid XML"):
        xml_support.load_xml_root(malformed_path)


def test_xml_helpers_cover_namespaces_targets_tokens_and_severity() -> None:
    namespaced_root = Element("{urn:nessus}NessusClientData_v2")
    assert xml_support.looks_like_nessus_document(namespaced_root) is True
    assert xml_support.xml_local_name("{urn:test}ReportHost") == "reporthost"

    report_root = fromstring("<root><ReportHost /></root>")
    assert xml_support.looks_like_nessus_document(report_root) is True

    openvas_result = fromstring(
        """
        <result>
          <nvt>
            <cve>CVE-2024-0002</cve>
            <refs>
              <ref type="cve" id="CVE-2024-0003" />
              <ref type="url" id="CVE-2024-9999" />
              <ref type="cve">CVE-2024-0003</ref>
            </refs>
          </nvt>
        </result>
        """
    )
    assert xml_support.looks_like_openvas_document(openvas_result) is True
    assert xml_support.openvas_cve_tokens(openvas_result) == [
        "CVE-2024-0002",
        "CVE-2024-0003",
    ]

    report_host = fromstring(
        """
        <ReportHost>
          <HostProperties>
            <ignored>skip</ignored>
            <tag name="host-ip">10.0.0.1</tag>
          </HostProperties>
        </ReportHost>
        """
    )
    assert xml_support.nessus_target_ref(report_host, 1) == "10.0.0.1"
    assert xml_support.nessus_target_ref(Element("ReportHost", {"name": "fallback"}), 2) == (
        "fallback"
    )
    assert xml_support.nessus_target_ref(Element("ReportHost"), 3) == "nessus-host-3"

    report_item = fromstring(
        """
        <ReportItem>
          <risk_factor> High </risk_factor>
          <cve>CVE-2024-0004, CVE-2024-0004 invalid</cve>
        </ReportItem>
        """
    )
    assert xml_support.nessus_cve_tokens(report_item) == ["CVE-2024-0004", "invalid"]
    assert xml_support.nessus_service_label(report_item) is None
    assert xml_support.nessus_severity(report_item) == "High"
    assert xml_support.nessus_severity(Element("ReportItem", {"severity": "3"})) == "3"
    assert xml_support.xml_child_text(fromstring("<root><name> </name></root>"), "name") is None
    assert xml_support.xml_child_text(Element("root"), "missing") is None

    warnings: list[str] = []
    assert xml_support.normalize_cve_tokens(
        ["CVE-2024-0005", "not-a-cve"],
        source_name="Nessus",
        target_ref="10.0.0.1",
        warnings=warnings,
    ) == ["CVE-2024-0005"]
    assert "Ignored non-CVE Nessus identifier" in warnings[0]


def test_detect_input_format_covers_xml_and_json_auto_detection(tmp_path: Path) -> None:
    explicit = tmp_path / "anything.custom"
    explicit.write_text("", encoding="utf-8")
    assert detect_input_format(explicit, explicit_format="trivy-json") == "trivy-json"

    nessus_file = tmp_path / "scan.nessus"
    nessus_file.write_text("", encoding="utf-8")
    assert detect_input_format(nessus_file) == "nessus-xml"

    unknown_xml = tmp_path / "unknown.xml"
    unknown_xml.write_text("<root />", encoding="utf-8")
    with pytest.raises(ValueError, match="Unable to auto-detect the XML input format"):
        detect_input_format(unknown_xml)

    unsupported = tmp_path / "input.yaml"
    unsupported.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="non-.txt/.csv/.json/.xml/.nessus"):
        detect_input_format(unsupported)

    cases = [
        ("trivy.json", {"Results": []}, "trivy-json"),
        ("grype.json", {"matches": []}, "grype-json"),
        ("cyclonedx.json", {"bomFormat": "CycloneDX"}, "cyclonedx-json"),
        ("spdx.json", {"spdxVersion": "SPDX-2.3"}, "spdx-json"),
        ("dependency-check.json", {"scanInfo": {}, "dependencies": []}, "dependency-check-json"),
        ("github-alerts-list.json", [], "github-alerts-json"),
        ("github-alerts-object.json", {"alerts": []}, "github-alerts-json"),
        ("github-advisory.json", {"security_advisory": {}}, "github-alerts-json"),
    ]
    for filename, payload, expected_format in cases:
        input_file = tmp_path / filename
        input_file.write_text(json.dumps(payload), encoding="utf-8")
        assert detect_input_format(input_file) == expected_format

    unknown_json = tmp_path / "unknown.json"
    unknown_json.write_text(json.dumps({"unknown": True}), encoding="utf-8")
    with pytest.raises(ValueError, match="Unable to auto-detect the JSON input format"):
        detect_input_format(unknown_json)
