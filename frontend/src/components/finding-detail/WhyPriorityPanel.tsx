import type {
  FindingDetailPublic,
  FindingExplanationPublic,
} from "@/api-client"
import { formatNullableNumber } from "@/lib/risk-format"

import type { FindingDecisionReason } from "./finding-detail-model"
import { FindingRationaleLedger } from "./FindingRationaleLedger"
import {
  compactFindingText,
  findingGovernanceActionNote,
  findingGovernanceStatus,
  findingRecommendedAction,
  findingRecommendedActionParts,
  findingWhyText,
} from "./finding-detail-model"

function governanceStateTitle(finding: FindingDetailPublic) {
  switch (findingGovernanceStatus(finding)) {
    case "suppressed":
      return "Suppressed by VEX statement"
    case "accepted":
      return "Accepted risk under waiver"
    case "fixed":
      return "Confirmed fixed"
    default:
      return "Owner action"
  }
}

export type WhyPriorityPanelProps = {
  decisionReasons: readonly FindingDecisionReason[]
  explanation: FindingExplanationPublic | null
  finding: FindingDetailPublic
  reasonRows: readonly { detail: string; label: string }[]
}

function countProviderReasons(
  reasonRows: readonly { detail: string; label: string }[],
  pattern: RegExp,
) {
  return reasonRows.filter((reason) =>
    pattern.test(`${reason.label} ${reason.detail}`),
  ).length
}

function providerReasonText(
  reasonRows: readonly { detail: string; label: string }[],
  pattern: RegExp,
) {
  const matched = reasonRows.some((reason) =>
    pattern.test(`${reason.label} ${reason.detail}`),
  )
  return matched
}

function primaryDriverLabel(
  finding: FindingDetailPublic,
  decisionReasons: readonly FindingDecisionReason[],
) {
  if (finding.in_kev) {
    return "CISA KEV"
  }
  if (finding.epss !== null && finding.epss !== undefined && finding.epss >= 0.7) {
    return "High EPSS"
  }
  if (
    finding.cvss_base_score !== null &&
    finding.cvss_base_score !== undefined &&
    finding.cvss_base_score >= 9
  ) {
    return "Critical CVSS"
  }
  return decisionReasons[0]?.label ?? "Stored rationale"
}

export function WhyPriorityPanel({
  decisionReasons,
  explanation,
  finding,
  reasonRows,
}: WhyPriorityPanelProps) {
  const whyText = findingWhyText(finding, explanation)
  const recommendedAction = findingRecommendedAction(finding, explanation)
  const action = findingRecommendedActionParts(recommendedAction)
  const governanceNote = findingGovernanceActionNote(finding)
  const scoreInputs = countProviderReasons(
    reasonRows,
    /score|priority|threshold|escalation|operational/i,
  )
  const signalSummary = [
    providerReasonText(reasonRows, /kev|cisa/i) ? "KEV" : null,
    providerReasonText(reasonRows, /epss/i) ? "EPSS" : null,
    providerReasonText(reasonRows, /cvss|severity/i) ? "CVSS" : null,
  ].filter((value): value is string => Boolean(value))
  const contextSummary = [
    providerReasonText(
      reasonRows,
      /asset|context|environment|owner|service|production|internet/i,
    )
      ? "Asset context"
      : null,
    providerReasonText(reasonRows, /vex|governance/i) ? "VEX status" : null,
    scoreInputs > 0 ? "Score rules" : null,
  ].filter((value): value is string => Boolean(value))

  return (
    <section
      aria-label="Risk to decision"
      className="finding-decision-section"
    >
      <div className="finding-decision-section__header">
        <div>
          <span>Decision</span>
          <h3>Why this priority?</h3>
          <p>
            The ranking is explained from stored scanner, provider, asset, and
            governance evidence before any raw audit details.
          </p>
        </div>
      </div>

      <div className="finding-decision-brief">
        <div className="finding-decision-brief__primary">
          <span>Decision summary</span>
          <p title={whyText}>{compactFindingText(whyText, 360)}</p>
        </div>
        <dl className="finding-decision-brief__facts">
          <div>
            <dt>Risk score</dt>
            <dd>{formatNullableNumber(finding.risk_score)}</dd>
          </div>
          <div>
            <dt>Primary driver</dt>
            <dd>{primaryDriverLabel(finding, decisionReasons)}</dd>
          </div>
          <div>
            <dt>Signals</dt>
            <dd>{decisionReasons.length} active</dd>
          </div>
          <div>
            <dt>Decision basis</dt>
            <dd>Scanner + provider evidence</dd>
          </div>
        </dl>
      </div>

      <section
        aria-label="Owner action summary"
        className="finding-decision-owner-summary"
      >
        <span>{governanceNote ? "Governance state" : "Owner action"}</span>
        <strong>
          {governanceNote ? governanceStateTitle(finding) : action.title}
        </strong>
        <p title={governanceNote ?? recommendedAction}>
          {governanceNote ?? action.detail}
        </p>
      </section>

      <div className="finding-decision-reasons-heading">
        <span>Decision drivers</span>
        <strong>Ordered active signals</strong>
      </div>
      <ol className="finding-decision-reasons">
        {decisionReasons.map((reason, index) => (
          <li data-tone={reason.tone} key={`${reason.label}:${reason.detail}`}>
            <span>{index + 1}</span>
            <div>
              <strong>{reason.label}</strong>
              <p>{reason.detail}</p>
            </div>
          </li>
        ))}
      </ol>

      <FindingRationaleLedger
        contextSummary={contextSummary}
        reasonRows={reasonRows}
        signalSummary={signalSummary}
      />
    </section>
  )
}
