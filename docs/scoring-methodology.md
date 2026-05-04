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
