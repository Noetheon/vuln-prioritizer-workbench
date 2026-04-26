"""Parsers for safe local XML scanner exports."""

from __future__ import annotations

from pathlib import Path

from vuln_prioritizer.models import InputOccurrence, ParsedInput

from .. import _xml_support


def parse_nessus_xml(path: Path) -> ParsedInput:
    root = _xml_support.load_xml_root(path)
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    report_hosts = _xml_support.xml_descendants(root, "reporthost")

    total_rows = 0
    for host_index, report_host in enumerate(report_hosts, start=1):
        target_ref = _xml_support.nessus_target_ref(report_host, host_index)
        report_items = [
            element
            for element in report_host
            if _xml_support.xml_local_name(element.tag) == "reportitem"
        ]
        for item_index, report_item in enumerate(report_items, start=1):
            total_rows += 1
            cve_ids = _xml_support.normalize_cve_tokens(
                _xml_support.nessus_cve_tokens(report_item),
                source_name="Nessus",
                target_ref=target_ref,
                warnings=warnings,
            )
            if not cve_ids:
                continue
            component_name = report_item.attrib.get("pluginName") or _xml_support.xml_child_text(
                report_item,
                "plugin_name",
            )
            service = _xml_support.nessus_service_label(report_item)
            record_id = (
                f"host:{host_index}:target:{target_ref}:item:{item_index}:"
                f"plugin:{report_item.attrib.get('pluginID') or 'unknown'}"
            )
            for cve_id in cve_ids:
                occurrences.append(
                    InputOccurrence(
                        cve_id=cve_id,
                        source_format="nessus-xml",
                        component_name=component_name,
                        component_version=service,
                        package_type="nessus-plugin",
                        source_record_id=record_id,
                        raw_severity=_xml_support.nessus_severity(report_item),
                        target_kind="host",
                        target_ref=target_ref,
                    )
                )

    return ParsedInput(
        input_format="nessus-xml",
        total_rows=total_rows,
        occurrences=occurrences,
        warnings=warnings,
    )


def parse_openvas_xml(path: Path) -> ParsedInput:
    root = _xml_support.load_xml_root(path)
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    results = _xml_support.xml_descendants(root, "result")

    for result_index, result in enumerate(results, start=1):
        target_ref = (
            _xml_support.xml_child_text(result, "host")
            or _xml_support.xml_child_text(result, "hostname")
            or _xml_support.xml_child_text(result, "ip")
            or f"openvas-target-{result_index}"
        )
        cve_ids = _xml_support.normalize_cve_tokens(
            _xml_support.openvas_cve_tokens(result),
            source_name="OpenVAS",
            target_ref=target_ref,
            warnings=warnings,
        )
        if not cve_ids:
            continue
        nvt = _xml_support.xml_child(result, "nvt")
        component_name = _xml_support.xml_child_text(result, "name") or (
            None if nvt is None else _xml_support.xml_child_text(nvt, "name")
        )
        for cve_id in cve_ids:
            occurrences.append(
                InputOccurrence(
                    cve_id=cve_id,
                    source_format="openvas-xml",
                    component_name=component_name,
                    package_type="openvas-nvt",
                    source_record_id=f"result:{result_index}",
                    raw_severity=_xml_support.xml_child_text(result, "severity")
                    or _xml_support.xml_child_text(result, "threat"),
                    target_kind="host",
                    target_ref=target_ref,
                )
            )

    return ParsedInput(
        input_format="openvas-xml",
        total_rows=len(results),
        occurrences=occurrences,
        warnings=warnings,
    )
