"""Shared ATT&CK source identifiers and guardrail constants."""

from __future__ import annotations

ATTACK_SOURCE_NONE = "none"
ATTACK_SOURCE_LOCAL_CSV = "local-csv"
ATTACK_SOURCE_CTID_JSON = "ctid-json"
ATTACK_SOURCE_CTID_MAPPINGS_EXPLORER = "ctid-mappings-explorer"

WORKBENCH_ATTACK_SOURCE_CTID = "ctid"
WORKBENCH_ATTACK_SOURCE_LOCAL_CURATED = "local_curated"
WORKBENCH_ATTACK_SOURCE_MANUAL = "manual"

WORKBENCH_ALLOWED_MAPPING_SOURCES = {
    WORKBENCH_ATTACK_SOURCE_CTID,
    WORKBENCH_ATTACK_SOURCE_LOCAL_CURATED,
    WORKBENCH_ATTACK_SOURCE_MANUAL,
}
WORKBENCH_DISALLOWED_MAPPING_SOURCES = {"heuristic"}
WORKBENCH_DISALLOWED_MAPPING_SOURCE_PREFIXES = ("llm", "llm_")

LEGACY_LOCAL_CSV_WARNING = (
    "ATT&CK source local-csv is a legacy compatibility mode; "
    "prefer --attack-source ctid-json for structured CTID-backed ATT&CK context."
)
LEGACY_LOCAL_CSV_RATIONALE = (
    "Legacy local ATT&CK CSV context is available for this CVE. "
    "Prefer --attack-source ctid-json for structured CTID-backed ATT&CK context."
)
