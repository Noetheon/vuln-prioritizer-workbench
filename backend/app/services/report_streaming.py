"""Bounded historical exports using the same projection and redaction as reports."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable, Iterator
from typing import Any

from app.services.report_exports import analysis_result_value, render_findings_csv
from app.services.report_governance_projection import _waiver_record
from app.services.report_models import MarkdownReportFinding
from app.services.report_projection import _analysis_finding
from app.services.report_renderer_common import _redact_bundle_value, _redact_report_finding
from app.services.report_service_payload import ReportSource


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _redact(value: Any, path: str) -> Any:
    return _redact_bundle_value(value, path_prefix=path)[0]


def stream_analysis_json(
    source: ReportSource, *, checkpoint: Callable[[], None] | None = None
) -> Iterator[bytes]:
    """
    Keep one evidence batch, compact rollup inputs and disk-backed explanations.

    The v2 explanations map retains the last ranked scope for each CVE, as before.
    Spooling avoids retaining full explanations for every distinct CVE in memory.
    Only redacted content reaches the temporary file; it closes on every exit.
    """
    compact: list[MarkdownReportFinding] = []
    offsets: dict[str, tuple[int, int]] = {}
    with tempfile.TemporaryFile() as explanations:
        yield b'{"findings":['
        for index, (finding, _) in enumerate(source.findings(checkpoint)):
            # Preserve raw governance semantics, then redact the completed rollup.
            compact.append(
                finding.model_copy(
                    update={
                        "evidence": {},
                        "explanation": {"waiver": _waiver_record(finding)},
                        "occurrences": (),
                        "vulnerability": None,
                        "data_quality": {},
                        "rationale": None,
                        "recommended_action": None,
                        "decision_statement": None,
                        "business_impact": None,
                        "decision_sla": None,
                        "data_quality_flags": (),
                    }
                )
            )
            redacted = _redact_report_finding(finding, index=index, redact=_redact)
            if index:
                yield b","
            yield _json_bytes(_analysis_finding(redacted))
            if redacted.explanation:
                value = _json_bytes(redacted.explanation)
                offsets[redacted.cve_id] = (explanations.tell(), len(value))
                explanations.write(value)
        yield b'],"explanations":{'
        for index, cve_id in enumerate(sorted(offsets)):
            if index:
                yield b","
            yield _json_bytes(cve_id) + b":"
            offset, size = offsets[cve_id]
            explanations.seek(offset)
            while size:
                chunk = explanations.read(min(size, 64 * 1024))
                size -= len(chunk)
                yield chunk
        yield b"}"
        header = source.payload(compact).model_copy(update={"findings": ()})
        values = analysis_result_value(header)
        for key in sorted(values):
            if key not in {"findings", "explanations"}:
                yield b"," + _json_bytes(key) + b":" + _json_bytes(values[key])
        yield b"}\n"


def stream_findings_csv(
    source: ReportSource, *, checkpoint: Callable[[], None] | None = None
) -> Iterator[bytes]:
    """Render the existing spreadsheet-safe row contract without collecting findings."""
    header = render_findings_csv(source.header)
    yield header.encode("utf-8")
    for finding, _ in source.findings(checkpoint):
        content = render_findings_csv(source.header.model_copy(update={"findings": (finding,)}))
        yield content[len(header) :].encode("utf-8")
