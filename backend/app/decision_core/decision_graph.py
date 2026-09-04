"""Scope-first decision graph for Workbench analysis results."""

from __future__ import annotations

import json
import zlib
from collections import Counter, defaultdict
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Literal, overload

from pydantic import Field

from app.decision_core.identity import finding_scope_parts
from app.decision_core.ledger import canonical_payload_sha256
from app.domain.engine.model_base import StrictModel
from app.domain.engine.models import (
    AnalysisContext,
    AttackData,
    ContextPolicyProfile,
    DefensiveContext,
    EpssData,
    InputOccurrence,
    KevData,
    NvdData,
    PrioritizedFinding,
    ProviderDataQualityFlag,
    ProviderEvidence,
    WaiverRule,
)
from app.domain.engine.services.contextualization import (
    aggregate_provenance,
    load_context_profile,
)
from app.domain.engine.services.decision_guidance import DecisionGuidanceService
from app.domain.engine.services.prioritization import PrioritizationService
from app.domain.engine.services.prioritization_ranking import global_operational_sort_key
from app.domain.engine.services.waivers import (
    apply_waivers,
    waiver_matches_finding,
    waiver_rule_label,
)

DECISION_GRAPH_SCHEMA_VERSION: Literal["scope-first-decision-graph.v2"] = (
    "scope-first-decision-graph.v2"
)
DECISION_REPLAY_SCHEMA_VERSION: Literal["scope-first-decision-replay.v2"] = (
    "scope-first-decision-replay.v2"
)
SCOPED_DECISION_STORAGE_VERSION: Literal["scoped-decision-zlib-v1"] = "scoped-decision-zlib-v1"
_MAX_SCOPED_DECISION_BYTES = 16 * 1024 * 1024


class ScopeKey(StrictModel):
    """Project-independent identity of one final finding decision scope."""

    cve_id: str
    component_identity: str | None
    target_kind: str
    target_ref: str | None

    @classmethod
    def from_occurrence(cls, occurrence: InputOccurrence) -> ScopeKey:
        """Build the canonical finding scope represented by an occurrence."""
        parts = finding_scope_parts(
            cve_id=occurrence.cve_id,
            component_name=occurrence.component_name,
            component_version=occurrence.component_version,
            purl=occurrence.purl,
            package_type=occurrence.package_type,
            asset_id=occurrence.asset_id,
            target_kind=occurrence.target_kind,
            target_ref=occurrence.target_ref,
        )
        return cls(
            cve_id=parts.cve_id,
            component_identity=parts.component_identity,
            target_kind=parts.target_kind,
            target_ref=parts.target_ref,
        )

    def parts(self) -> dict[str, str | None]:
        """Return canonical project-independent identity material."""
        return {
            "cve_id": self.cve_id,
            "component_identity": self.component_identity,
            "target_kind": self.target_kind,
            "target_ref": self.target_ref,
        }

    def sort_key(
        self,
    ) -> tuple[str, tuple[bool, str], str, tuple[bool, str]]:
        """Return a deterministic ordering key for global ranking ties."""
        return (
            self.cve_id,
            _optional_sort_key(self.component_identity),
            self.target_kind,
            _optional_sort_key(self.target_ref),
        )


class SharedCveFacts(StrictModel):
    """Provider and ATT&CK facts shared by every scope for one CVE."""

    cve_id: str
    provider_evidence: ProviderEvidence
    attack_data: AttackData
    data_quality_flags: list[ProviderDataQualityFlag] = Field(default_factory=list)
    data_quality_confidence: str = "high"
    defensive_contexts: list[DefensiveContext] = Field(default_factory=list)


class DecisionReplayFingerprint(StrictModel):
    """Deterministic hashes of the available inputs to one graph evaluation."""

    schema_version: Literal["scope-first-decision-replay.v2"] = DECISION_REPLAY_SCHEMA_VERSION
    analysis_schema_version: str
    evaluation_time: str
    normalized_input_sha256: str
    policy_sha256: str
    shared_facts_sha256: str
    provider_snapshot_hash: str | None = None
    attack_mapping_file_sha256: str | None = None
    attack_technique_metadata_file_sha256: str | None = None
    replay_sha256: str


class ScopedFindingDecision(StrictModel):
    """One fully evaluated finding decision at its final domain scope."""

    scope_key: ScopeKey
    decision: PrioritizedFinding
    observation_source_ids: list[str] = Field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _StoredScopedDecision:
    """Compressed internal representation with metadata needed by graph indexes."""

    scope_key: ScopeKey
    priority_label: str
    operational_rank: int
    suppressed_by_vex: bool
    under_investigation: bool
    waived: bool
    waiver_status: str | None
    sort_key: tuple[Any, ...]
    payload: bytes = field(repr=False)

    @classmethod
    def from_decision(
        cls,
        item: ScopedFindingDecision,
        *,
        sort_key: tuple[Any, ...],
    ) -> _StoredScopedDecision:
        raw = item.model_dump_json().encode("utf-8")
        if len(raw) > _MAX_SCOPED_DECISION_BYTES:
            raise ValueError("Scoped decision exceeds the supported in-memory size limit.")
        return cls(
            scope_key=item.scope_key,
            priority_label=item.decision.priority_label,
            operational_rank=item.decision.operational_rank,
            suppressed_by_vex=item.decision.suppressed_by_vex,
            under_investigation=item.decision.under_investigation,
            waived=item.decision.waived,
            waiver_status=item.decision.waiver_status,
            sort_key=sort_key,
            payload=zlib.compress(raw, level=6),
        )

    def materialize(self) -> ScopedFindingDecision:
        """Restore one typed decision without retaining all decisions at once."""
        decompressor = zlib.decompressobj()
        limit = _MAX_SCOPED_DECISION_BYTES + 1
        try:
            raw = decompressor.decompress(self.payload, limit)
            if decompressor.unconsumed_tail or len(raw) >= limit:
                raise ValueError("Compressed scoped decision exceeds its size limit.")
            raw += decompressor.flush(limit - len(raw))
        except zlib.error as exc:
            raise ValueError("Compressed scoped decision is corrupt.") from exc
        if len(raw) >= limit or not decompressor.eof or decompressor.unused_data:
            raise ValueError("Compressed scoped decision is corrupt or truncated.")
        return ScopedFindingDecision.model_validate_json(raw)


@dataclass(frozen=True, slots=True)
class _ScopedDecisionView(Sequence[ScopedFindingDecision]):
    """Lazy sequence preserving the public scoped-decisions API."""

    records: tuple[_StoredScopedDecision, ...]

    def __len__(self) -> int:
        return len(self.records)

    @overload
    def __getitem__(self, index: int) -> ScopedFindingDecision: ...

    @overload
    def __getitem__(self, index: slice) -> list[ScopedFindingDecision]: ...

    def __getitem__(
        self,
        index: int | slice,
    ) -> ScopedFindingDecision | list[ScopedFindingDecision]:
        if isinstance(index, slice):
            return [record.materialize() for record in self.records[index]]
        return self.records[index].materialize()

    def __iter__(self) -> Iterator[ScopedFindingDecision]:
        return (record.materialize() for record in self.records)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _ScopedDecisionView):
            return self.records == other.records
        if not isinstance(other, Sequence):
            return False
        return len(self) == len(other) and all(
            left == right for left, right in zip(self, other, strict=True)
        )


@dataclass(frozen=True, slots=True)
class DecisionGraph:
    """Shared facts and a lazy, compressed store of scoped decisions."""

    shared_facts_by_cve: dict[str, SharedCveFacts]
    counts_by_priority: dict[str, int]
    waiver_warnings: tuple[str, ...]
    superseded_waiver_warnings: tuple[str, ...]
    fingerprint: DecisionReplayFingerprint
    _stored_decisions: tuple[_StoredScopedDecision, ...] = field(repr=False)
    schema_version: Literal["scope-first-decision-graph.v2"] = DECISION_GRAPH_SCHEMA_VERSION
    storage_version: Literal["scoped-decision-zlib-v1"] = SCOPED_DECISION_STORAGE_VERSION
    _scope_index: dict[
        tuple[str, tuple[bool, str], str, tuple[bool, str]],
        _StoredScopedDecision,
    ] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        """Build the O(1) index and validate compact decision metadata."""
        scope_index = {item.scope_key.sort_key(): item for item in self._stored_decisions}
        if len(scope_index) != len(self._stored_decisions):
            raise ValueError("Decision graph contains duplicate scope keys.")
        if any(
            item.scope_key.cve_id not in self.shared_facts_by_cve for item in self._stored_decisions
        ):
            raise ValueError("Decision graph contains a scope without shared CVE facts.")
        ranks = sorted(item.operational_rank for item in self._stored_decisions)
        if ranks != list(range(1, len(self._stored_decisions) + 1)):
            raise ValueError("Decision graph operational ranks must be globally unique.")
        actual_counts = dict(Counter(item.priority_label for item in self._stored_decisions))
        if actual_counts != self.counts_by_priority:
            raise ValueError("Decision graph priority counts do not match scoped decisions.")
        object.__setattr__(self, "_scope_index", scope_index)

    @property
    def scoped_decisions(self) -> Sequence[ScopedFindingDecision]:
        """Expose value-equivalent decisions through a lazy sequence."""
        return _ScopedDecisionView(self._stored_decisions)

    @property
    def decision_count(self) -> int:
        """Return the number of final finding scopes without materialization."""
        return len(self._stored_decisions)

    @property
    def suppressed_by_vex_count(self) -> int:
        """Return the number of suppressed scopes from compact metadata."""
        return sum(item.suppressed_by_vex for item in self._stored_decisions)

    @property
    def under_investigation_count(self) -> int:
        """Return the number of scopes under investigation from compact metadata."""
        return sum(item.under_investigation for item in self._stored_decisions)

    @property
    def waived_count(self) -> int:
        """Return active/review-due accepted-risk scopes from compact metadata."""
        return sum(item.waived for item in self._stored_decisions)

    @property
    def waiver_review_due_count(self) -> int:
        """Return scopes whose waiver review is due."""
        return sum(item.waiver_status == "review_due" for item in self._stored_decisions)

    @property
    def expired_waiver_count(self) -> int:
        """Return scopes carrying an expired waiver record."""
        return sum(item.waiver_status == "expired" for item in self._stored_decisions)

    def decision_for(self, scope_key: ScopeKey) -> ScopedFindingDecision | None:
        """Return the decision for an exact canonical scope, when present."""
        stored = self._scope_index.get(scope_key.sort_key())
        return stored.materialize() if stored is not None else None

    def scope_index(self) -> Mapping[ScopeKey, ScopedFindingDecision]:
        """Return an explicitly materialized caller-owned lookup snapshot."""
        return {item.scope_key: item.materialize() for item in self._stored_decisions}

    def decision_for_occurrence(
        self,
        occurrence: InputOccurrence,
    ) -> ScopedFindingDecision | None:
        """Look up a decision using the shared analysis/persistence scope normalization."""
        return self.decision_for(ScopeKey.from_occurrence(occurrence))


def build_scoped_decision_graph(
    *,
    findings_by_cve: Mapping[str, PrioritizedFinding],
    occurrences: Sequence[InputOccurrence],
    context: AnalysisContext,
    context_profile: ContextPolicyProfile | None = None,
    waiver_rules: Sequence[WaiverRule] = (),
) -> DecisionGraph:
    """Re-evaluate decision semantics after grouping observations by final scope."""
    baselines = _normalized_baselines(findings_by_cve)
    active_waiver_rules = list(waiver_rules)
    if not active_waiver_rules and any(_has_waiver_state(item) for item in baselines.values()):
        raise ValueError(
            "Scope-first evaluation requires the original waiver rules; "
            "CVE-level waiver state cannot be projected safely."
        )
    active_context_profile = context_profile or _context_profile_from_context(context)
    waiver_evaluation_date = _evaluation_date(context)
    shared_facts = {
        cve_id: _shared_facts(baseline) for cve_id, baseline in sorted(baselines.items())
    }
    grouped = _group_occurrences_by_scope(
        baselines=baselines,
        occurrences=occurrences,
    )
    prioritizer = PrioritizationService(policy=context.priority_policy)
    stored_decisions: list[_StoredScopedDecision] = []
    scoped_waiver_warnings: set[str] = set()
    matched_waiver_labels: set[str] = set()
    waiver_rules_by_cve: defaultdict[str, list[WaiverRule]] = defaultdict(list)
    for rule in active_waiver_rules:
        waiver_rules_by_cve[rule.cve_id].append(rule)
    for scope_key, scoped_occurrences in sorted(
        grouped.items(),
        key=lambda item: item[0].sort_key(),
    ):
        decision, scope_warnings, scope_matched_labels = _evaluate_scope(
            scope_key=scope_key,
            occurrences=scoped_occurrences,
            shared_facts=shared_facts[scope_key.cve_id],
            prioritizer=prioritizer,
            context_profile=active_context_profile,
            waiver_rules=waiver_rules_by_cve[scope_key.cve_id],
            waiver_evaluation_date=waiver_evaluation_date,
        )
        scoped_waiver_warnings.update(scope_warnings)
        matched_waiver_labels.update(scope_matched_labels)
        stored_decisions.append(
            _StoredScopedDecision.from_decision(
                decision,
                sort_key=global_operational_sort_key(
                    decision.decision,
                    decision.scope_key.sort_key(),
                ),
            )
        )
    ranked_decisions = _assign_global_ranks(stored_decisions)
    counts_by_priority = dict(Counter(item.priority_label for item in ranked_decisions))
    for rule in active_waiver_rules:
        label = waiver_rule_label(rule)
        if label not in matched_waiver_labels:
            scoped_waiver_warnings.add(f"Waiver {label} did not match any finding.")
    _aggregate_findings, aggregate_waiver_warnings = apply_waivers(
        list(baselines.values()),
        active_waiver_rules,
        today=waiver_evaluation_date,
    )
    fingerprint = _build_fingerprint(
        context=context,
        context_profile=active_context_profile,
        occurrences=occurrences,
        shared_facts=shared_facts,
        waiver_rules=active_waiver_rules,
        waiver_evaluation_date=waiver_evaluation_date,
    )
    return DecisionGraph(
        shared_facts_by_cve=shared_facts,
        counts_by_priority=counts_by_priority,
        waiver_warnings=tuple(sorted(scoped_waiver_warnings)),
        superseded_waiver_warnings=tuple(sorted(set(aggregate_waiver_warnings))),
        fingerprint=fingerprint,
        _stored_decisions=tuple(ranked_decisions),
    )


def _normalized_baselines(
    findings_by_cve: Mapping[str, PrioritizedFinding],
) -> dict[str, PrioritizedFinding]:
    baselines: dict[str, PrioritizedFinding] = {}
    for map_key, finding in findings_by_cve.items():
        cve_id = finding.cve_id.strip().upper()
        if map_key.strip().upper() != cve_id:
            raise ValueError(f"Decision baseline key does not match finding CVE: {map_key!r}.")
        if cve_id in baselines:
            raise ValueError(f"Decision analysis produced duplicate CVE facts for {cve_id}.")
        baselines[cve_id] = finding
    return baselines


def _group_occurrences_by_scope(
    *,
    baselines: Mapping[str, PrioritizedFinding],
    occurrences: Sequence[InputOccurrence],
) -> dict[ScopeKey, list[InputOccurrence]]:
    grouped: defaultdict[ScopeKey, list[InputOccurrence]] = defaultdict(list)
    seen_cves: set[str] = set()
    for occurrence in _sorted_occurrences(occurrences):
        scope_key = ScopeKey.from_occurrence(occurrence)
        if scope_key.cve_id not in baselines:
            raise ValueError(f"Occurrence scope {scope_key.cve_id} has no shared decision facts.")
        grouped[scope_key].append(occurrence)
        seen_cves.add(scope_key.cve_id)

    for cve_id in sorted(set(baselines) - seen_cves):
        synthetic = InputOccurrence(cve_id=cve_id)
        grouped[ScopeKey.from_occurrence(synthetic)].append(synthetic)
    return dict(grouped)


def _evaluate_scope(
    *,
    scope_key: ScopeKey,
    occurrences: list[InputOccurrence],
    shared_facts: SharedCveFacts,
    prioritizer: PrioritizationService,
    context_profile: ContextPolicyProfile,
    waiver_rules: list[WaiverRule],
    waiver_evaluation_date: date,
) -> tuple[ScopedFindingDecision, list[str], set[str]]:
    cve_id = scope_key.cve_id
    provenance = aggregate_provenance([cve_id], occurrences)[cve_id]
    provider = shared_facts.provider_evidence
    decisions, _ = prioritizer.prioritize(
        [cve_id],
        nvd_data={cve_id: provider.nvd},
        epss_data={cve_id: provider.epss},
        kev_data={cve_id: provider.kev},
        attack_data={cve_id: shared_facts.attack_data},
        provenance_by_cve={cve_id: provenance},
        context_profile=context_profile,
    )
    decision = decisions[0]
    scoped_provider = decision.provider_evidence or provider
    scoped_provider = scoped_provider.model_copy(
        update={"defensive_contexts": list(shared_facts.defensive_contexts)}
    )
    decision = decision.model_copy(
        update={
            "provider_evidence": scoped_provider,
            "defensive_contexts": list(shared_facts.defensive_contexts),
            "data_quality_flags": list(shared_facts.data_quality_flags),
            "data_quality_confidence": shared_facts.data_quality_confidence,
        }
    )
    waiver_warnings: list[str] = []
    matched_labels: set[str] = set()
    if waiver_rules:
        matched_labels = {
            waiver_rule_label(rule)
            for rule in waiver_rules
            if waiver_matches_finding(rule, decision)
        }
        scoped_with_waivers, waiver_warnings = apply_waivers(
            [decision],
            waiver_rules,
            today=waiver_evaluation_date,
            include_unmatched_warnings=False,
        )
        decision = scoped_with_waivers[0]
    decision = prioritizer.assign_operational_ranks([decision])[0]
    return (
        ScopedFindingDecision(
            scope_key=scope_key,
            decision=decision,
            observation_source_ids=sorted(
                {occurrence.source_id for occurrence in occurrences if occurrence.source_id}
            ),
        ),
        waiver_warnings,
        matched_labels,
    )


def _assign_global_ranks(
    decisions: list[_StoredScopedDecision],
) -> list[_StoredScopedDecision]:
    ordered = sorted(decisions, key=lambda item: item.sort_key)
    guidance_service = DecisionGuidanceService()
    for rank, stored in enumerate(ordered, start=1):
        item = stored.materialize()
        ranked_decision = item.decision.model_copy(update={"operational_rank": rank})
        ranked_decision = ranked_decision.model_copy(
            update={"decision_guidance": guidance_service.build(ranked_decision)}
        )
        ranked_item = item.model_copy(update={"decision": ranked_decision})
        ordered[rank - 1] = _StoredScopedDecision.from_decision(
            ranked_item,
            sort_key=stored.sort_key,
        )
        del item, ranked_decision, ranked_item
    return ordered


def _shared_facts(finding: PrioritizedFinding) -> SharedCveFacts:
    provider = finding.provider_evidence or ProviderEvidence(
        nvd=NvdData(
            cve_id=finding.cve_id,
            description=finding.description,
            cvss_base_score=finding.cvss_base_score,
            cvss_severity=finding.cvss_severity,
            cvss_version=finding.cvss_version,
        ),
        epss=EpssData(
            cve_id=finding.cve_id,
            epss=finding.epss,
            percentile=finding.epss_percentile,
        ),
        kev=KevData(cve_id=finding.cve_id, in_kev=finding.in_kev),
    )
    defensive_contexts = list(finding.defensive_contexts or provider.defensive_contexts)
    if provider.defensive_contexts != defensive_contexts:
        provider = provider.model_copy(update={"defensive_contexts": defensive_contexts})
    attack_context = finding.attack_context
    mappings = list(finding.attack_mappings or attack_context.mappings)
    techniques = list(finding.attack_technique_details or attack_context.techniques)
    attack_data = AttackData(
        cve_id=finding.cve_id,
        mapped=finding.attack_mapped,
        source=attack_context.source,
        source_version=attack_context.source_version,
        attack_version=attack_context.attack_version,
        domain=attack_context.domain,
        mappings=mappings,
        techniques=techniques,
        mapping_types=sorted(
            {mapping.mapping_type for mapping in mappings if mapping.mapping_type}
        ),
        capability_groups=sorted(
            {mapping.capability_group for mapping in mappings if mapping.capability_group}
        ),
        attack_relevance=finding.attack_relevance,
        attack_rationale=finding.attack_rationale,
        attack_techniques=list(finding.attack_techniques),
        attack_tactics=list(finding.attack_tactics),
        attack_note=finding.attack_note,
    )
    return SharedCveFacts(
        cve_id=finding.cve_id.strip().upper(),
        provider_evidence=provider,
        attack_data=attack_data,
        data_quality_flags=list(finding.data_quality_flags),
        data_quality_confidence=finding.data_quality_confidence,
        defensive_contexts=defensive_contexts,
    )


def _context_profile_from_context(context: AnalysisContext) -> ContextPolicyProfile:
    try:
        return load_context_profile(context.policy_profile, None)
    except ValueError:
        return ContextPolicyProfile(name=context.policy_profile)


def _build_fingerprint(
    *,
    context: AnalysisContext,
    context_profile: ContextPolicyProfile,
    occurrences: Sequence[InputOccurrence],
    shared_facts: Mapping[str, SharedCveFacts],
    waiver_rules: Sequence[WaiverRule],
    waiver_evaluation_date: date,
) -> DecisionReplayFingerprint:
    input_hash = canonical_payload_sha256(
        {
            "occurrences": [
                occurrence.model_dump(mode="json")
                for occurrence in _sorted_occurrences(occurrences)
            ]
        }
    )
    policy_hash = canonical_payload_sha256(
        {
            "priority_policy": context.priority_policy.model_dump(mode="json"),
            "context_profile": context_profile.model_dump(mode="json"),
            "policy_overrides": sorted(context.policy_overrides),
            "waiver_rules": sorted(
                (rule.model_dump(mode="json") for rule in waiver_rules),
                key=lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")),
            ),
            "waiver_evaluation_date": (
                waiver_evaluation_date.isoformat() if waiver_rules else None
            ),
        }
    )
    shared_facts_hash = canonical_payload_sha256(
        {
            "shared_facts_by_cve": {
                cve_id: facts.model_dump(mode="json")
                for cve_id, facts in sorted(shared_facts.items())
            }
        }
    )
    replay_material = {
        "schema_version": DECISION_REPLAY_SCHEMA_VERSION,
        "analysis_schema_version": context.schema_version,
        "normalized_input_sha256": input_hash,
        "policy_sha256": policy_hash,
        "shared_facts_sha256": shared_facts_hash,
        "provider_snapshot_hash": context.provider_snapshot_hash,
        "attack_mapping_file_sha256": context.attack_mapping_file_sha256,
        "attack_technique_metadata_file_sha256": (context.attack_technique_metadata_file_sha256),
    }
    return DecisionReplayFingerprint(
        analysis_schema_version=context.schema_version,
        evaluation_time=context.generated_at,
        normalized_input_sha256=input_hash,
        policy_sha256=policy_hash,
        shared_facts_sha256=shared_facts_hash,
        provider_snapshot_hash=context.provider_snapshot_hash,
        attack_mapping_file_sha256=context.attack_mapping_file_sha256,
        attack_technique_metadata_file_sha256=(context.attack_technique_metadata_file_sha256),
        replay_sha256=canonical_payload_sha256(replay_material),
    )


def _sorted_occurrences(
    occurrences: Sequence[InputOccurrence],
) -> list[InputOccurrence]:
    return sorted(
        occurrences,
        key=lambda occurrence: json.dumps(
            occurrence.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
    )


def _evaluation_date(context: AnalysisContext) -> date:
    try:
        return date.fromisoformat(context.generated_at.strip()[:10])
    except ValueError as exc:
        raise ValueError("Analysis generated_at must contain a valid evaluation date.") from exc


def _has_waiver_state(finding: PrioritizedFinding) -> bool:
    return bool(
        finding.waived
        or finding.waiver_status
        or finding.waiver_reason
        or finding.waiver_id
        or finding.waiver_matched_scope
    )


def _optional_sort_key(value: str | None) -> tuple[bool, str]:
    return value is not None, value or ""
