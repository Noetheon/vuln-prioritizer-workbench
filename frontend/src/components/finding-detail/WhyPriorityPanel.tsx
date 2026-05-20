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
import { findingWhyText } from "./finding-detail-model"

export type WhyPriorityPanelProps = {
  decisionReasons: readonly FindingDecisionReason[]
  explanation: FindingExplanationPublic | null
  finding: FindingDetailPublic
  occurrences: readonly FindingOccurrenceRow[]
  onRefresh: () => void
  reasonRows: readonly { detail: string; label: string }[]
  waiverEvidence: FindingWaiverEvidence | null
}

export function WhyPriorityPanel({
  decisionReasons,
  explanation,
  finding,
  onRefresh,
  reasonRows,
}: WhyPriorityPanelProps) {
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
            Score {formatNullableNumber(finding.risk_score)} is explained with
            the available scanner, provider, asset, and governance context.
          </p>
        </div>
        <Button onClick={onRefresh} size="sm" type="button" variant="outline">
          Refresh evidence
        </Button>
      </div>

      <p className="finding-decision-lead">
        {findingWhyText(finding, explanation)}
      </p>

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
          <summary>Provider explanation</summary>
          <dl>
            {reasonRows.map((reason) => (
              <div key={`${reason.label}:${reason.detail}`}>
                <dt>{labelize(reason.label)}</dt>
                <dd>{reason.detail}</dd>
              </div>
            ))}
          </dl>
        </details>
      ) : null}
    </section>
  )
}
