import type {
  FindingDetailPublic,
  FindingExplanationPublic,
} from "@/api-client"
import {
  CvssBadge,
  EpssBadge,
  FindingStatusBadge,
  KevBadge,
  PriorityBadge,
} from "@/components/risk"
import { VpwBadge } from "@/components/vpw"
import { formatNullableNumber } from "@/lib/risk-format"

import {
  type FindingOccurrenceRow,
  findingComponentDetailLabel,
  findingHeroSummary,
  findingRecommendedAction,
  findingSlaLabel,
} from "./finding-detail-model"

export type FindingDetailHeroProps = {
  explanation: FindingExplanationPublic | null
  finding: FindingDetailPublic
  isDemo: boolean
  occurrences: readonly FindingOccurrenceRow[]
}

export function FindingDetailHero({
  explanation,
  finding,
  isDemo,
}: FindingDetailHeroProps) {
  return (
    <>
      {isDemo ? (
        <section aria-label="Demo Preview" className="finding-demo-preview">
          <VpwBadge tone="warning">Demo Preview</VpwBadge>
          <span>
            Sample evidence for the decision workflow. Not real production data.
          </span>
        </section>
      ) : null}

      <section
        aria-label="Finding decision summary"
        className="finding-detail-header-band"
      >
        <div className="finding-detail-header-copy">
          <VpwBadge className="finding-detail-kicker" tone="info">
            Triage decision
          </VpwBadge>
          <h2>{finding.cve_id}</h2>
          <p className="finding-detail-component-line">
            {findingComponentDetailLabel(finding)}
          </p>
          <p>{findingHeroSummary(finding, explanation)}</p>
          <div className="finding-decision-badges">
            <PriorityBadge priority={finding.priority} />
            <FindingStatusBadge status={finding.status} />
            <KevBadge matched={finding.in_kev} />
          </div>
        </div>

        <div className="finding-detail-header-action">
          <span>Owner action</span>
          <strong>{findingRecommendedAction(finding, explanation)}</strong>
          <small>
            {findingSlaLabel(finding.priority)} SLA from current risk signals.
          </small>
        </div>

        <ul
          aria-label="Risk indicators"
          className="finding-detail-header-metrics"
        >
          <li>
            <span>Risk score</span>
            <strong>{formatNullableNumber(finding.risk_score)}</strong>
            <small>Operational priority</small>
          </li>
          <li>
            <span>EPSS</span>
            <EpssBadge value={finding.epss} />
            <small>Probability signal</small>
          </li>
          <li>
            <span>CVSS</span>
            <CvssBadge value={finding.cvss_base_score} />
            <small>Impact signal</small>
          </li>
          <li>
            <span>SLA</span>
            <strong>{findingSlaLabel(finding.priority)}</strong>
            <small>Response target</small>
          </li>
        </ul>
      </section>
    </>
  )
}
