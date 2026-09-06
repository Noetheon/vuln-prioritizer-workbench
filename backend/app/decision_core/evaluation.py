"""Complete, deterministic scope evaluation from explicit replayable inputs."""

from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import Field, model_validator

from app.decision_core.identity import finding_scope_parts
from app.decision_core.ledger import canonical_payload_sha256
from app.domain.engine.model_base import StrictModel
from app.domain.engine.models import (
    AttackData,
    ContextPolicyProfile,
    DefensiveContext,
    InputOccurrence,
    PrioritizedFinding,
    PriorityPolicy,
    ProviderDataQualityFlag,
    ProviderEvidence,
    WaiverRule,
)
from app.domain.engine.services.contextualization import aggregate_provenance
from app.domain.engine.services.prioritization import PrioritizationService
from app.domain.engine.services.waivers import apply_waivers

EVALUATION_ENGINE_VERSION = "scope-evaluator.v1"


class ScopeEvaluationInput(StrictModel):
    """Immutable-in-storage inputs sufficient for a complete offline scope replay."""

    schema_version: Literal["scope-evaluation-input.v1"] = "scope-evaluation-input.v1"
    engine_version: str = EVALUATION_ENGINE_VERSION
    cve_id: str
    observations: list[InputOccurrence]
    provider_evidence: ProviderEvidence
    attack_data: AttackData
    priority_policy: PriorityPolicy = Field(default_factory=PriorityPolicy)
    context_profile: ContextPolicyProfile = Field(default_factory=ContextPolicyProfile)
    waiver_rules: list[WaiverRule] = Field(default_factory=list)
    workbench_waiver: WaiverRule | None = None
    evaluation_date: date
    data_quality_flags: list[ProviderDataQualityFlag] = Field(default_factory=list)
    data_quality_confidence: str = "high"
    defensive_contexts: list[DefensiveContext] = Field(default_factory=list)

    @model_validator(mode="after")
    def consistent_cve_identity(self) -> ScopeEvaluationInput:
        """Reject mixed CVE inputs instead of silently evaluating another scope."""
        identities = [
            self.provider_evidence.nvd.cve_id,
            self.provider_evidence.epss.cve_id,
            self.provider_evidence.kev.cve_id,
            self.attack_data.cve_id,
            *(item.cve_id for item in self.observations),
        ]
        if not self.observations or any(value != self.cve_id for value in identities):
            raise ValueError("Evaluation inputs must contain observations and facts for one CVE.")
        scopes = {
            finding_scope_parts(
                cve_id=item.cve_id,
                component_name=item.component_name,
                component_version=item.component_version,
                purl=item.purl,
                package_type=item.package_type,
                asset_id=item.asset_id,
                target_kind=item.target_kind,
                target_ref=item.target_ref,
            )
            for item in self.observations
        }
        if len(scopes) != 1:
            raise ValueError("Evaluation observations must belong to one finding scope.")
        return self

    def fingerprint(self) -> str:
        """Hash all actual inputs, including policy and date, without implicit defaults."""
        return canonical_payload_sha256(self.model_dump(mode="json"))


def evaluate_scope(inputs: ScopeEvaluationInput) -> PrioritizedFinding:
    """Evaluate every decision field through the same pure domain transformation."""
    return evaluate_scope_with_diagnostics(inputs)[0]


def evaluate_scope_with_diagnostics(
    inputs: ScopeEvaluationInput,
) -> tuple[PrioritizedFinding, list[str]]:
    """Return the decision and rule diagnostics from one evaluation pass."""
    if inputs.engine_version != EVALUATION_ENGINE_VERSION:
        raise ValueError(f"Unsupported evaluation engine: {inputs.engine_version}")
    cve_id = inputs.cve_id
    provider = inputs.provider_evidence
    provenance = aggregate_provenance([cve_id], inputs.observations)[cve_id]
    prioritizer = PrioritizationService(policy=inputs.priority_policy)
    decisions, _ = prioritizer.prioritize(
        [cve_id],
        nvd_data={cve_id: provider.nvd},
        epss_data={cve_id: provider.epss},
        kev_data={cve_id: provider.kev},
        attack_data={cve_id: inputs.attack_data},
        provenance_by_cve={cve_id: provenance},
        context_profile=inputs.context_profile,
        finalize=False,
    )
    decision = decisions[0].model_copy(
        update={
            "provider_evidence": provider.model_copy(
                update={"defensive_contexts": list(inputs.defensive_contexts)}
            ),
            "defensive_contexts": list(inputs.defensive_contexts),
            "data_quality_flags": list(inputs.data_quality_flags),
            "data_quality_confidence": inputs.data_quality_confidence,
        }
    )
    waiver_rules = [inputs.workbench_waiver] if inputs.workbench_waiver else inputs.waiver_rules
    warnings: list[str] = []
    if waiver_rules:
        decisions, warnings = apply_waivers(
            [decision],
            waiver_rules,
            today=inputs.evaluation_date,
            include_unmatched_warnings=False,
        )
        decision = decisions[0]
    return prioritizer.assign_operational_ranks([decision])[0], warnings
