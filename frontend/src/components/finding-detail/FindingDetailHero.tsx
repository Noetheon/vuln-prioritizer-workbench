import type {
  FindingDetailPublic,
  FindingExplanationPublic,
} from "@/api-client"
import { CvssBadge, EpssBadge } from "@/components/risk"
import {
  RiskBadge,
  RiskScoreBadge,
  SignalChip,
  StatusLozenge,
  VpwBadge,
} from "@/components/vpw"

import {
  type FindingOccurrenceRow,
  compactFindingText,
  findingComponentDetailLabel,
  findingHeroSummary,
  findingRecommendedAction,
  findingRecommendedActionParts,
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
  const recommendedAction = findingRecommendedAction(finding, explanation)
  const action = findingRecommendedActionParts(recommendedAction)
  const recommendationSummary = compactFindingText(
    `${action.title}. Validate affected assets, then record the fix path in Triage.`,
    150,
  )

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
          <p title={findingHeroSummary(finding, explanation)}>
            {compactFindingText(findingHeroSummary(finding, explanation), 220)}
          </p>
          <div className="finding-decision-badges">
            <RiskBadge level={finding.priority} />
            <StatusLozenge status={finding.status} />
            {finding.in_kev ? <SignalChip kind="kev" /> : null}
            {finding.epss !== null && finding.epss !== undefined ? (
              <SignalChip kind="epss" value={finding.epss} />
            ) : null}
            {finding.cvss_base_score !== null &&
            finding.cvss_base_score !== undefined ? (
              <SignalChip kind="cvss" value={finding.cvss_base_score} />
            ) : null}
          </div>
          <p
            className="finding-detail-recommendation-line"
            title={recommendedAction}
          >
            <span>Recommended action</span>
            {recommendationSummary}
          </p>
        </div>

        <ul
          aria-label="Risk indicators"
          className="finding-detail-header-metrics"
        >
          <li>
            <span>Risk score</span>
            <strong>
              <RiskScoreBadge value={finding.risk_score} />
            </strong>
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
