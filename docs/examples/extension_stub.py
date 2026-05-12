"""Static parser/provider extension example for contributor documentation.

This module is intentionally a docs example and test fixture. It is not imported
by the runtime and does not perform plugin discovery.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from vuln_prioritizer.inputs.sdk import InputParserDefinition
from vuln_prioritizer.models import InputOccurrence, InputSourceSummary, ParsedInput
from vuln_prioritizer.providers.sdk import ProviderDefinition


def parse_acme_scan(path: Path) -> ParsedInput:
    """Parse a tiny reviewed JSON fixture into the Workbench ParsedInput contract."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    records = payload.get("findings", [])
    occurrences: list[InputOccurrence] = []
    for index, record in enumerate(records, start=1):
        cve_id = str(record.get("cve", "")).strip().upper()
        if not cve_id:
            continue
        occurrences.append(
            InputOccurrence(
                cve_id=cve_id,
                source_format="acme-scan-json",
                source_record_id=str(record.get("id") or index),
                component_name=record.get("component"),
                component_version=record.get("version"),
                raw_severity=record.get("severity"),
                target_kind="container",
                target_ref=record.get("asset"),
            )
        )

    unique_cves = sorted({occurrence.cve_id for occurrence in occurrences})
    return ParsedInput(
        input_format="acme-scan-json",
        total_rows=len(records),
        occurrences=occurrences,
        unique_cves=unique_cves,
        source_stats={"acme-scan-json": len(occurrences)},
        input_paths=[str(path)],
        source_summaries=[
            InputSourceSummary(
                input_path=str(path),
                input_format="acme-scan-json",
                total_rows=len(records),
                occurrence_count=len(occurrences),
                unique_cves=len(unique_cves),
            )
        ],
        included_occurrence_count=len(occurrences),
        included_unique_cves=len(unique_cves),
    )


class AcmeContextProvider:
    """Small reviewed local provider stub that returns deterministic records."""

    def __init__(self) -> None:
        self.last_diagnostics: Any = None

    def fetch_many(
        self,
        cve_ids: list[str],
        **_kwargs: Any,
    ) -> tuple[Mapping[str, Any], list[str]]:
        self.last_diagnostics = type(
            "Diagnostics",
            (),
            {
                "requested": len(cve_ids),
                "content_hits": len(cve_ids),
                "failures": 0,
                "degraded": False,
            },
        )()
        records = {
            cve_id: {
                "source": "acme-context",
                "review_status": "fixture-only",
                "note": "Reviewed local context only; not an exploit signal.",
            }
            for cve_id in cve_ids
        }
        return records, []


ACME_SCAN_PARSER = InputParserDefinition(
    name="acme-scan-json",
    parser=parse_acme_scan,
    file_suffixes=(".acme.json",),
    media_types=("application/json",),
    fixture_names=(
        "acme-scan-json/positive.acme.json",
        "acme-scan-json/negative.acme.json",
    ),
)

ACME_CONTEXT_PROVIDER = ProviderDefinition(
    name="acme-context",
    provider=AcmeContextProvider(),
    source_kind="reviewed-local-context",
    cache_namespace="acme-context",
    cache_key_template="{cve_id}",
    offline_capable=True,
)
