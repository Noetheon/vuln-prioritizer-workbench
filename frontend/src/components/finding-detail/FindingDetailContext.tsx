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
  findingGovernanceActionNote,
  findingGovernanceStatus,
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
  const governanceStatus = findingGovernanceStatus(finding)
  const governanceNote = findingGovernanceActionNote(finding)
  const recommendationSummary = compactFindingText(
    `${action.title}. Validate affected assets, then record the fix path in Triage.`,
    150,
  )
  const riskMetrics: MetricStripMetric[] = [
    {
      description: governanceStatus ? "Residual signal score" : "Operational priority",
      label: "Risk score",
      tone: governanceStatus ? "info" : "critical",
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
      description: governanceStatus ? "Governance state" : "Response target",
      label: "SLA",
      tone: "success",
      value: findingSlaLabel(finding.priority, finding.status),
    },
  ]

  return (
    <VpwCommandPanel
      actions={
        <div className="finding-decision-badges">
          <RiskBadge level={finding.priority} />
          <StatusLozenge status={finding.status} />
          {finding.in_kev ? <SignalChip kind="kev" /> : null}
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
        governanceNote ? (
          <>
            <span className="font-semibold text-[var(--vpw-text-primary)]">
              Governance state:{" "}
            </span>
            <span>{governanceNote}</span>
          </>
        ) : (
          <>
            <span className="font-semibold text-[var(--vpw-text-primary)]">
              Recommended action:{" "}
            </span>
            <span title={recommendedAction}>{recommendationSummary}</span>
          </>
        )
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
