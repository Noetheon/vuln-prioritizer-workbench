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
  RiskScore,
} from "@/components/risk"
import {
  VpwBadge,
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import { formatNullableNumber } from "@/lib/risk-format"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"

import {
  type FindingOccurrenceRow,
  findingAssetServiceDetailLabel,
  findingComponentDetailLabel,
  findingHeroSummary,
  findingOwnerDetailLabel,
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
  occurrences,
}: FindingDetailHeroProps) {
  const assetEnvironmentLabel = finding.asset_environment
    ? labelize(finding.asset_environment)
    : "Environment not recorded"

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
        className="finding-decision-hero"
        aria-label="Finding decision hero"
      >
        <div className="finding-decision-hero-copy">
          <VpwBadge className="finding-decision-kicker" tone="info">
            Why this priority?
          </VpwBadge>
          <h2>{finding.cve_id}</h2>
          <p>{findingHeroSummary(finding, explanation)}</p>
          <div className="finding-decision-badges">
            <PriorityBadge priority={finding.priority} />
            <FindingStatusBadge status={finding.status} />
            <KevBadge matched={finding.in_kev} />
          </div>
        </div>
        <ul
          className="finding-decision-hero-metrics"
          aria-label="Risk indicators"
        >
          <li className="finding-hero-metric-primary">
            <span>Risk Score</span>
            <strong>{formatNullableNumber(finding.risk_score)}</strong>
            <small>Operational remediation priority</small>
          </li>
          <li className="finding-hero-metric-support">
            <span>EPSS</span>
            <EpssBadge value={finding.epss} />
            <small>Exploit probability signal</small>
          </li>
          <li className="finding-hero-metric-support">
            <span>CVSS</span>
            <CvssBadge value={finding.cvss_base_score} />
            <small>Impact severity signal</small>
          </li>
          <li className="finding-hero-metric-decision">
            <span>Decision</span>
            <RiskScore value={finding.risk_score} />
            <small>{findingSlaLabel(finding.priority)} SLA</small>
          </li>
        </ul>
      </section>

      <section
        className="finding-decision-fact-grid"
        aria-label="Finding scope"
      >
        <VpwSurface className="finding-fact-card">
          <VpwSurfaceHeader>
            <VpwSurfaceDescription>Component</VpwSurfaceDescription>
            <VpwSurfaceTitle
              className="finding-fact-card-title"
              title={findingComponentDetailLabel(finding)}
            >
              {findingComponentDetailLabel(finding)}
            </VpwSurfaceTitle>
          </VpwSurfaceHeader>
          <VpwSurfaceBody>
            <p title={optionalText(finding.component_purl)}>
              {optionalText(finding.component_purl)}
            </p>
          </VpwSurfaceBody>
        </VpwSurface>
        <VpwSurface className="finding-fact-card">
          <VpwSurfaceHeader>
            <VpwSurfaceDescription>Asset / Service</VpwSurfaceDescription>
            <VpwSurfaceTitle
              className="finding-fact-card-title"
              title={findingAssetServiceDetailLabel(finding)}
            >
              {findingAssetServiceDetailLabel(finding)}
            </VpwSurfaceTitle>
          </VpwSurfaceHeader>
          <VpwSurfaceBody>
            <p>{labelize(finding.exposure)}</p>
          </VpwSurfaceBody>
        </VpwSurface>
        <VpwSurface className="finding-fact-card">
          <VpwSurfaceHeader>
            <VpwSurfaceDescription>Owner</VpwSurfaceDescription>
            <VpwSurfaceTitle className="finding-fact-card-title">
              {findingOwnerDetailLabel(finding, occurrences)}
            </VpwSurfaceTitle>
          </VpwSurfaceHeader>
          <VpwSurfaceBody>
            <p>{assetEnvironmentLabel}</p>
          </VpwSurfaceBody>
        </VpwSurface>
        <VpwSurface className="finding-fact-card finding-recommendation-card">
          <VpwSurfaceHeader>
            <VpwSurfaceDescription>
              Primary recommendation
            </VpwSurfaceDescription>
            <VpwSurfaceTitle className="finding-fact-card-title">
              {findingRecommendedAction(finding, explanation)}
            </VpwSurfaceTitle>
          </VpwSurfaceHeader>
        </VpwSurface>
      </section>
    </>
  )
}
