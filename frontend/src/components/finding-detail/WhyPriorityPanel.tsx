import type {
  FindingDetailPublic,
  FindingExplanationPublic,
} from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwBadge,
  VpwKeyValueList,
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import { formatNullableNumber } from "@/lib/risk-format"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"
import type { FindingWaiverEvidence } from "@/lib/waiver-view"

import type {
  FindingDecisionReason,
  FindingOccurrenceRow,
} from "./finding-detail-model"
import {
  findingNextStepLabel,
  findingOwnerDetailLabel,
  findingRecommendedAction,
  findingSlaLabel,
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

export function WhyPriorityPanel({
  decisionReasons,
  explanation,
  finding,
  occurrences,
  onRefresh,
  reasonRows,
  waiverEvidence,
}: WhyPriorityPanelProps) {
  const owner = findingOwnerDetailLabel(finding, occurrences)

  return (
    <section
      className="finding-decision-main-grid"
      aria-label="Risk to decision"
    >
      <VpwSurface className="finding-decision-card finding-analysis-card">
        <VpwSurfaceHeader>
          <div className="finding-card-heading">
            <div>
              <VpwSurfaceDescription>Risk to Decision</VpwSurfaceDescription>
              <VpwSurfaceTitle className="finding-card-title">
                Why this priority?
              </VpwSurfaceTitle>
            </div>
            <VpwBadge tone="info">
              Score {formatNullableNumber(finding.risk_score)}
            </VpwBadge>
          </div>
        </VpwSurfaceHeader>
        <VpwSurfaceBody>
          <p className="finding-decision-lead">
            {findingWhyText(finding, explanation)}
          </p>
          <ol
            aria-label="Risk to decision chain"
            className="finding-decision-chain"
          >
            <li>Finding</li>
            <li>Priority</li>
            <li>Evidence</li>
            <li>Decision</li>
          </ol>
          <dl className="finding-decision-reasons">
            {decisionReasons.map((reason) => (
              <div
                data-tone={reason.tone}
                key={`${reason.label}:${reason.detail}`}
              >
                <dt>{reason.label}</dt>
                <dd>{reason.detail}</dd>
              </div>
            ))}
          </dl>
          {reasonRows.length > 0 ? (
            <div className="finding-provider-reasons">
              <span>Provider explanation</span>
              <dl>
                {reasonRows.map((reason) => (
                  <div key={`${reason.label}:${reason.detail}`}>
                    <dt>{labelize(reason.label)}</dt>
                    <dd>{reason.detail}</dd>
                  </div>
                ))}
              </dl>
            </div>
          ) : null}
        </VpwSurfaceBody>
      </VpwSurface>

      <VpwSurface className="finding-decision-card finding-action-card">
        <VpwSurfaceHeader>
          <VpwSurfaceDescription>Remediation</VpwSurfaceDescription>
          <VpwSurfaceTitle className="finding-card-title">
            Decision plan
          </VpwSurfaceTitle>
        </VpwSurfaceHeader>
        <VpwSurfaceBody>
          <VpwKeyValueList
            className="finding-decision-definition-list"
            items={[
              {
                label: "Recommended action",
                value: findingRecommendedAction(finding, explanation),
              },
              {
                label: "SLA",
                value: findingSlaLabel(finding.priority),
              },
              {
                label: "Owner",
                value: owner,
              },
              {
                label: "Next step",
                value: findingNextStepLabel(finding),
              },
              {
                label: "Risk acceptance option",
                value: waiverEvidence
                  ? `${optionalText(waiverEvidence.status)} — ${optionalText(waiverEvidence.reason)}`
                  : "Available only with owner, expiry, approval reference, and compensating evidence.",
              },
            ]}
          />
          <div className="finding-decision-actions">
            <Button
              onClick={onRefresh}
              size="sm"
              type="button"
              variant="outline"
            >
              Refresh evidence
            </Button>
          </div>
        </VpwSurfaceBody>
      </VpwSurface>
    </section>
  )
}
