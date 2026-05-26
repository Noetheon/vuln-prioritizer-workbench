"""Stable ATT&CK model facade for the Workbench backend."""

from __future__ import annotations

from app.models.attack_catalog import (
    AttackTactic,
    AttackTacticBase,
    AttackTacticPublic,
    AttackTechnique,
    AttackTechniqueBase,
    AttackTechniquePublic,
    CveAttackMapping,
    CveAttackMappingBase,
    CveAttackMappingPublic,
)
from app.models.attack_common import ATTACK_MAPPING_TYPES, ATTACK_REVIEW_STATUSES
from app.models.attack_context import (
    FindingAttackContext,
    FindingAttackContextBase,
    FindingAttackContextPublic,
)
from app.models.attack_stix import (
    AttackStixMitigation,
    AttackStixMitigationBase,
    AttackStixSnapshot,
    AttackStixSnapshotBase,
    AttackStixSnapshotPublic,
    AttackStixTactic,
    AttackStixTacticBase,
    AttackStixTechnique,
    AttackStixTechniqueBase,
    AttackStixTechniqueMitigation,
    AttackStixTechniqueMitigationBase,
)
from app.models.attack_summary import (
    AttackSummaryContextRow,
    AttackSummaryFindingRow,
    ProjectAttackSummaryPublic,
    ProjectAttackTacticSummaryPublic,
    ProjectAttackTechniqueSummaryPublic,
)

_FACADE_EXPORTS = (
    AttackStixMitigation,
    AttackStixMitigationBase,
    AttackStixSnapshot,
    AttackStixSnapshotBase,
    AttackStixSnapshotPublic,
    AttackStixTactic,
    AttackStixTacticBase,
    AttackStixTechnique,
    AttackStixTechniqueBase,
    AttackStixTechniqueMitigation,
    AttackStixTechniqueMitigationBase,
    AttackSummaryContextRow,
    AttackSummaryFindingRow,
    AttackTactic,
    AttackTacticBase,
    AttackTacticPublic,
    AttackTechnique,
    AttackTechniqueBase,
    AttackTechniquePublic,
    CveAttackMapping,
    CveAttackMappingBase,
    CveAttackMappingPublic,
    FindingAttackContext,
    FindingAttackContextBase,
    FindingAttackContextPublic,
    ProjectAttackSummaryPublic,
    ProjectAttackTacticSummaryPublic,
    ProjectAttackTechniqueSummaryPublic,
)

for _export in _FACADE_EXPORTS:
    _export.__module__ = __name__

del _export

__all__ = [
    "ATTACK_MAPPING_TYPES",
    "ATTACK_REVIEW_STATUSES",
    "AttackStixMitigation",
    "AttackStixMitigationBase",
    "AttackStixSnapshot",
    "AttackStixSnapshotBase",
    "AttackStixSnapshotPublic",
    "AttackStixTactic",
    "AttackStixTacticBase",
    "AttackStixTechnique",
    "AttackStixTechniqueBase",
    "AttackStixTechniqueMitigation",
    "AttackStixTechniqueMitigationBase",
    "AttackSummaryContextRow",
    "AttackSummaryFindingRow",
    "AttackTactic",
    "AttackTacticBase",
    "AttackTacticPublic",
    "AttackTechnique",
    "AttackTechniqueBase",
    "AttackTechniquePublic",
    "CveAttackMapping",
    "CveAttackMappingBase",
    "CveAttackMappingPublic",
    "FindingAttackContext",
    "FindingAttackContextBase",
    "FindingAttackContextPublic",
    "ProjectAttackSummaryPublic",
    "ProjectAttackTacticSummaryPublic",
    "ProjectAttackTechniqueSummaryPublic",
]
