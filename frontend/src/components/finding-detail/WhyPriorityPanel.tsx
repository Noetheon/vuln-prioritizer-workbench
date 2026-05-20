import type {
  FindingDetailPublic,
  FindingExplanationPublic,
} from "@/api-client"
import { Button } from "@/components/ui/button"
import { formatNullableNumber } from "@/lib/risk-format"
import { formatLabel as labelize } from "@/lib/ui-copy"
import type { FindingWaiverEvidence } from "@/lib/waiver-view"

import type {
  FindingDecisionReason,
  FindingOccurrenceRow,
} from "./finding-detail-model"
import {
  compactFindingText,
  findingWhyText,
} from "./finding-detail-model"

export type WhyPriorityPanelProps = {
  decisionReasons: readonly FindingDecisionReason[]
  explanation: FindingExplanationPublic | null
  finding: FindingDetailPublic
  occurrences: readonly FindingOccurrenceRow[]
  onRefresh: () => void
  reasonRows: readonly { detail: string; label: string }[]
  waiverEvidence: FindingWaiverEvidence | null
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

export function WhyPriorityPanel({
  decisionReasons,
  explanation,
  finding,
  onRefresh,
  reasonRows,
}: WhyPriorityPanelProps) {
  const whyText = findingWhyText(finding, explanation)
  const scoreInputs = countProviderReasons(
    reasonRows,
    /score|priority|threshold|escalation|operational/i,
  )
  const signalSummary = [
    providerReasonText(reasonRows, /kev|exploited/i) ? "KEV" : null,
    providerReasonText(reasonRows, /epss/i) ? "EPSS" : null,
    providerReasonText(reasonRows, /cvss|severity/i) ? "CVSS" : null,
  ].filter(Boolean)
  const contextSummary = [
    providerReasonText(
      reasonRows,
      /asset|context|environment|owner|service|production|internet/i,
    )
      ? "Asset context"
      : null,
    providerReasonText(reasonRows, /vex|governance/i) ? "VEX status" : null,
    scoreInputs > 0 ? "Score rules" : null,
  ].filter(Boolean)

  return (
    <section
      aria-label="Risk to decision"
      className="finding-decision-section"
    >
      <div className="finding-decision-section__header">
        <div>
          <span>Decision record</span>
          <h3>Why this priority?</h3>
          <p>
            The priority is explained from stored scanner, provider, asset, and
            governance evidence.
          </p>
        </div>
        <Button onClick={onRefresh} size="sm" type="button" variant="outline">
          Refresh evidence
        </Button>
      </div>

      <div className="finding-decision-brief">
        <div className="finding-decision-brief__primary">
          <span>Why now</span>
          <p title={whyText}>{compactFindingText(whyText, 360)}</p>
        </div>
        <dl className="finding-decision-brief__facts">
          <div>
            <dt>Risk score</dt>
            <dd>{formatNullableNumber(finding.risk_score)}</dd>
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

      {reasonRows.length > 0 ? (
        <details className="finding-provider-reasons">
          <summary>
            <div>
              <span>Provider explanation</span>
              <strong>Stored rationale ledger</strong>
              <p>
                Audit trail from the provider decision payload. Use it to
                explain why this finding was ranked, not as extra remediation
                work.
              </p>
            </div>
            <div className="finding-provider-reasons__summary-action">
              <span className="finding-provider-reasons__count">
                {reasonRows.length} reason{reasonRows.length === 1 ? "" : "s"}
              </span>
            </div>
          </summary>
          <div className="finding-provider-reasons__body">
            <dl className="finding-provider-reasons__stats">
              <div>
                <dt>Signal evidence</dt>
                <dd>
                  {signalSummary.length > 0
                    ? signalSummary.join(", ")
                    : "No provider signal"}
                </dd>
              </div>
              <div>
                <dt>Context applied</dt>
                <dd>
                  {contextSummary.length > 0
                    ? contextSummary.join(", ")
                    : "No context applied"}
                </dd>
              </div>
              <div>
                <dt>Raw audit trail</dt>
                <dd>
                  {reasonRows.length} rationale rule
                  {reasonRows.length === 1 ? "" : "s"}
                </dd>
              </div>
            </dl>

            <div className="finding-provider-reasons__ledger-shell">
              <table className="finding-provider-reasons__ledger">
                <caption>Provider rationale statements</caption>
                <thead>
                  <tr>
                    <th scope="col">Reason</th>
                    <th scope="col">Provider statement</th>
                  </tr>
                </thead>
                <tbody>
                  {reasonRows.map((reason) => (
                    <tr key={`${reason.label}:${reason.detail}`}>
                      <th scope="row">{labelize(reason.label)}</th>
                      <td title={reason.detail}>
                        {compactFindingText(
                          reason.detail,
                          reason.detail.length > 160 ? 300 : 220,
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </details>
      ) : null}
    </section>
  )
}
