import type {
  FindingDetailPublic,
  FindingExplanationPublic,
} from "@/api-client"
import { formatEpss, formatNullableNumber } from "@/lib/risk-format"
import {
  VpwCommandPanel,
  MetricStrip,
  type MetricStripMetric,
  RiskBadge,
  SignalChip,
  StatusLozenge,
} from "@/components/vpw"

import {
  compactFindingText,
  findingComponentDetailLabel,
  findingHeroSummary,
  findingRecommendedAction,
  findingRecommendedActionParts,
  findingSlaLabel,
} from "./finding-detail-model"

export type FindingDetailContextProps = {
  explanation: FindingExplanationPublic | null
  finding: FindingDetailPublic
}

export function FindingDetailContext({
  explanation,
  finding,
}: FindingDetailContextProps) {
  const recommendedAction = findingRecommendedAction(finding, explanation)
  const action = findingRecommendedActionParts(recommendedAction)
  const recommendationSummary = compactFindingText(
    `${action.title}. Validate affected assets, then record the fix path in Triage.`,
    150,
  )
  const riskMetrics: MetricStripMetric[] = [
    {
      description: "Operational priority",
      label: "Risk score",
      tone: "critical",
      value: formatNullableNumber(finding.risk_score),
    },
    {
      description: "Probability signal",
      label: "EPSS",
      tone: "warning",
      value: formatEpss(finding.epss),
    },
    {
      description: "Impact signal",
      label: "CVSS",
      tone: "info",
      value: formatNullableNumber(finding.cvss_base_score),
    },
    {
      description: "Response target",
      label: "SLA",
      tone: "success",
      value: findingSlaLabel(finding.priority),
    },
  ]

  return (
    <VpwCommandPanel
      actions={
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
      }
      aria-label="Finding decision summary"
      className="finding-detail-context"
      description={
        <>
          <span className="font-semibold text-[var(--vpw-text-primary)]">
            {findingComponentDetailLabel(finding)}
          </span>{" "}
          {compactFindingText(findingHeroSummary(finding, explanation), 220)}
        </>
      }
      eyebrow="Triage decision"
      note={
        <>
          <span className="font-semibold text-[var(--vpw-text-primary)]">
            Recommended action:{" "}
          </span>
          <span title={recommendedAction}>{recommendationSummary}</span>
        </>
      }
      role="region"
      title={<span className="font-mono">{finding.cve_id}</span>}
    >
      <MetricStrip
        aria-label="Risk indicators"
        metrics={riskMetrics}
        minCardWidth="10.75rem"
      />
    </VpwCommandPanel>
  )
}
