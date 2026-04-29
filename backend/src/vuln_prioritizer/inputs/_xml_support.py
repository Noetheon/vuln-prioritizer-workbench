"""Private XML parsing helpers for Nessus and OpenVAS inputs."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from vuln_prioritizer.utils import normalize_cve_id


def load_xml_root(path: Path) -> ET.Element:
    raw = path.read_bytes()
    uppercase = raw.upper()
    if b"<!DOCTYPE" in uppercase or b"<!ENTITY" in uppercase:
        raise ValueError(
            "XML input contains a DOCTYPE or ENTITY declaration, which is not supported."
        )
    try:
        return ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError(f"XML input is not valid XML: {path}") from exc


def looks_like_nessus_document(root: ET.Element) -> bool:
    if xml_local_name(root.tag) in {"nessusclientdata_v2", "nessusclientdata"}:
        return True
    return xml_has_descendant(root, "reporthost")


def looks_like_openvas_document(root: ET.Element) -> bool:
    return xml_has_descendant(root, "result") and xml_has_descendant(root, "nvt")


def xml_local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", maxsplit=1)[1].lower()
    return tag.lower()


def xml_child(element: ET.Element, name: str) -> ET.Element | None:
    for child in element:
        if xml_local_name(child.tag) == name.lower():
            return child
    return None


def xml_child_text(element: ET.Element, name: str) -> str | None:
    child = xml_child(element, name)
    if child is None or child.text is None:
        return None
    text = child.text.strip()
    return text or None


def xml_descendants(root: ET.Element, name: str) -> list[ET.Element]:
    expected_name = name.lower()
    return [element for element in root.iter() if xml_local_name(element.tag) == expected_name]


def xml_has_descendant(root: ET.Element, name: str) -> bool:
    expected_name = name.lower()
    return any(xml_local_name(element.tag) == expected_name for element in root.iter())


def nessus_target_ref(report_host: ET.Element, host_index: int) -> str:
    host_properties = xml_child(report_host, "hostproperties")
    if host_properties is not None:
        preferred_names = ("host-fqdn", "host-ip", "host_dns", "netbios-name")
        tag_values: dict[str, str] = {}
        for tag in host_properties:
            if xml_local_name(tag.tag) != "tag":
                continue
            name = (tag.attrib.get("name") or "").strip().lower()
            value = (tag.text or "").strip()
            if name and value:
                tag_values[name] = value
        for preferred_name in preferred_names:
            if preferred_name in tag_values:
                return tag_values[preferred_name]

    for key in ("name",):
        attr_value = report_host.attrib.get(key)
        if attr_value:
            return attr_value.strip()

    return f"nessus-host-{host_index}"


def nessus_cve_tokens(report_item: ET.Element) -> list[str]:
    tokens: list[str] = []
    for child in report_item:
        if xml_local_name(child.tag) != "cve" or child.text is None:
            continue
        tokens.extend(split_cve_tokens(child.text))
    return deduplicate_preserving_order(tokens)


def openvas_cve_tokens(result: ET.Element) -> list[str]:
    tokens: list[str] = []
    nvt = xml_child(result, "nvt")
    if nvt is not None:
        cve_field = xml_child_text(nvt, "cve")
        if cve_field:
            tokens.extend(split_cve_tokens(cve_field))
        refs = xml_child(nvt, "refs")
        if refs is not None:
            for ref in refs:
                if xml_local_name(ref.tag) != "ref":
                    continue
                if (ref.attrib.get("type") or "").strip().lower() != "cve":
                    continue
                ref_id = (ref.attrib.get("id") or ref.text or "").strip()
                if ref_id:
                    tokens.extend(split_cve_tokens(ref_id))
    return deduplicate_preserving_order(tokens)


def normalize_cve_tokens(
    raw_tokens: list[str],
    *,
    source_name: str,
    target_ref: str,
    warnings: list[str],
) -> list[str]:
    cve_ids: list[str] = []
    for raw_cve in raw_tokens:
        cve_id = normalize_cve_id(raw_cve)
        if cve_id is None:
            warnings.append(
                f"Ignored non-CVE {source_name} identifier in {target_ref}: {raw_cve!r}"
            )
            continue
        cve_ids.append(cve_id)
    return cve_ids


def split_cve_tokens(value: str) -> list[str]:
    return [token.strip() for token in re.split(r"[\s,;]+", value) if token.strip()]


def deduplicate_preserving_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def nessus_service_label(report_item: ET.Element) -> str | None:
    svc_name = (report_item.attrib.get("svc_name") or "").strip()
    port = (report_item.attrib.get("port") or "").strip()
    protocol = (report_item.attrib.get("protocol") or "").strip()
    parts = [part for part in (svc_name, port, protocol) if part]
    if not parts:
        return None
    return "/".join(parts)


def nessus_severity(report_item: ET.Element) -> str | None:
    risk_factor = xml_child_text(report_item, "risk_factor")
    if risk_factor:
        return risk_factor
    severity = (report_item.attrib.get("severity") or "").strip()
    return severity or None
