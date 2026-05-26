"""Shared ATT&CK model validation helpers."""

from __future__ import annotations

from vuln_prioritizer.models_attack import (
    ATTACK_MAPPING_TYPES as CORE_ATTACK_MAPPING_TYPES,
)
from vuln_prioritizer.models_attack import (
    ATTACK_REVIEW_STATUSES as CORE_ATTACK_REVIEW_STATUSES,
)
from vuln_prioritizer.models_attack import (
    require_attack_non_empty_text,
    validate_attack_tactic_id,
    validate_attack_technique_id,
)

ATTACK_REVIEW_STATUSES = set(CORE_ATTACK_REVIEW_STATUSES)
ATTACK_MAPPING_TYPES = set(CORE_ATTACK_MAPPING_TYPES)

require_non_empty = require_attack_non_empty_text
validate_technique_id = validate_attack_technique_id
validate_tactic_id = validate_attack_tactic_id
