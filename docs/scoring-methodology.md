# Scoring Methodology

VPW prioritizes already-known CVEs using deterministic, explainable rules. It
does not use opaque machine-learning scoring and it does not infer exploitability
from unreviewed text.

## Base Priority

The base priority is rule-based from CVSS, FIRST EPSS, and CISA KEV:

| Priority | Rule |
| --- | --- |
| Critical | CISA KEV match, or EPSS >= 0.70 with CVSS >= 7.0 |
| High | EPSS >= 0.40, or CVSS >= 9.0 |
| Medium | CVSS >= 7.0, or EPSS >= 0.10 |
| Low | Everything else |

The base rule stays transparent so a finding can be explained in reports, API
responses, the Findings table, and Finding Detail.

## Signal Inputs

| Signal | Role |
| --- | --- |
| CVSS | Severity baseline from NVD/provider records. VPW records the selected CVSS family where available. |
| EPSS | Probability signal from FIRST EPSS. High EPSS can raise urgency even when CVSS alone is lower. |
| KEV | Known exploited vulnerability signal from CISA KEV. KEV makes a finding Critical in the base priority model. |
| Lifecycle status | Workbench state such as open, in review, remediating, resolved, accepted, and false positive keeps operational status visible. |
| Provider freshness | Stale, missing, or degraded provider data does not silently mark a finding safe; freshness is surfaced as data quality context. |
| Asset context | Owner, business service, exposure, environment, criticality, and asset identity help route remediation and governance rollups. |
| Waivers | Accepted-risk decisions are scoped, time-bound, and visible in lifecycle/governance context instead of deleting the finding. |
| VEX/applicability | Applicable, not affected, fixed, or under-investigation statements are handled as contextual evidence. Under-investigation stays visible. |

## Explanation Model

VPW produces human-readable priority reasons from the visible signal set. The
Finding Detail "Why this priority" view separates:

- base priority drivers: CVSS, EPSS, KEV
- occurrence and source provenance
- lifecycle and waiver context
- asset and service context
- ATT&CK/TTP context when explicitly mapped
- recommended action and SLA-oriented decision language

The UI and reports should show readable text, not internal keys such as
`priority.*`.

## Asset Context and Waivers

Asset context and waivers are governance context, not hidden scoring magic.

- Asset fields help identify owner, service, exposure, environment, and
  business criticality.
- Governance rollups group risk by owner, service, asset, and waiver debt.
- Waivers preserve accepted-risk decisions with owner, scope, approval,
  expiration, review date, and matching finding counts.
- Expired or review-due waivers remain visible as debt.

These signals can change operational ordering and decision language, but the
base CVSS/EPSS/KEV priority remains explainable.

## Operational Score Composition

The 0-100 operational score is additive and fully explainable. Every applied
rule emits one reason line that is persisted in decision evidence:

| Component | Points |
| --- | --- |
| Base priority | Critical +55, High +40, Medium +25, Low +10, Accepted +20 |
| CISA KEV listed | +12 |
| EPSS/CVSS signals | critical pair +8, high EPSS +5, high CVSS +5, medium tiers +2 |
| Internet-facing asset | +8 |
| Production environment | +4 |
| Asset criticality | critical +7, high +4, medium +2 |
| Additional active observations in the same finding scope | up to +5 |
| Accepted-risk waiver | -20 active, -5 review due |

The weights are deliberately balanced so that vulnerability signals alone do
not saturate the scale: only the combination of a critical vulnerability with
exposed, business-critical context reaches 100. This keeps asset context a
visible differentiator instead of dead weight behind a clamp.

### Scope-First Decisions

Provider enrichment remains shared per CVE, but VPW makes the operational
decision only after grouping observations by their final finding scope:

```text
normalized CVE + component identity + target kind + source target reference
```

For each scope, VPW independently aggregates provenance and derives VEX state,
remediation and fixed-version evidence, operational score and reasons,
explanation, decision guidance, and work-queue rank. Asset-context and VEX
sidecars therefore affect only the matching scope. A fixed version observed for
one component is not recommended for another component, and an
`under_investigation`, `fixed`, or `not_affected` statement does not leak to an
unmatched asset or component.

CVSS, EPSS, KEV, provider data-quality facts, and explicit ATT&CK context remain
shared CVE facts. They are reused rather than fetched once per asset. Base
priority is still derived from CVSS/EPSS/KEV, while context-dependent state and
operational ordering are evaluated per finding scope.

After every scope has been scored, VPW assigns globally unique operational
ranks `1..N` across the final finding set. Stable scope identity breaks complete
ties, so two findings for the same CVE cannot both receive rank 1.
Open Critical, High, Medium, and Low work is ordered ahead of governed terminal
states. Accepted risk follows open work, then VEX-suppressed and fixed evidence;
the operational score and the existing KEV, waiver, and asset-context signals
order findings within the same effective state.

Source records remain separate observations. Scanner `source_id` contributes
to provenance but is not part of finding identity; two scanners reporting the
same CVE/component/target converge on one finding scope. See
[Scope-First Decision Graph](architecture/scope-first-decision-graph.md) for
identity, replay, and persistence details.

## Data Quality and Gaps

VPW treats missing data as uncertainty:

- Missing CVSS means severity is unknown, not safe.
- Missing EPSS means probability is unavailable, not low.
- Missing KEV data means no KEV match was observed from the selected provider
  data, not proof that exploitation is impossible.
- Missing asset context means ownership and exposure need validation.
- Missing ATT&CK mapping means unmapped, not inferred.
- Stale provider data is shown as degraded freshness.

Reports and the Workbench should keep these limitations visible so a reviewer
can decide whether to refresh providers, add asset context, review waivers, or
collect better input evidence.

## Safety Boundary

The methodology is defensive prioritization. It does not:

- scan systems
- prove exploitation
- generate payloads or exploit steps
- autopatch assets
- claim ML-derived risk
- infer ATT&CK mappings from CVE text or vendor names

Human review remains required for final remediation, accepted-risk, and business
impact decisions.
