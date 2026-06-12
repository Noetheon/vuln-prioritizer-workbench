import {
  AlertTriangle,
  Globe2,
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
} from "lucide-react"
import type {
  FindingPublic,
  ProjectDecisionSummaryPublic,
  ProviderStatusPublic,
} from "@/api-client"
import { priorityCount } from "@/lib/chart-data"
import type {
  DashboardMetricSummary,
  DashboardSignalCounts,
} from "./dashboard-model"

export function providerNeedsRefresh(
  hasProviderStatus: boolean,
  providerStatus: ProviderStatusPublic | null,
) {
  return (
    hasProviderStatus &&
    providerStatus !== null &&
    (providerStatus.status !== "ok" ||
      Boolean(providerStatus.last_error) ||
      (providerStatus.warnings?.length ?? 0) > 0)
  )
}

export function rankedDashboardQueueFindings(
  findings: readonly FindingPublic[],
  queueSearch: string,
) {
  const ranked = [...findings].sort(
    (a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0),
  )
  const query = queueSearch.trim().toLowerCase()
  if (!query) return ranked
  return ranked.filter((finding) => {
    const fields = [
      finding.cve_id,
      finding.owner,
      finding.business_service,
      finding.component_name,
      finding.rationale,
      finding.recommended_action,
    ]
    return fields.some((field) => field?.toLowerCase().includes(query))
  })
}

export function buildDashboardMetricSummaries({
  acceptedRiskCount,
  effectiveSignalCounts,
  effectiveSummary,
  signalLoading,
  summaryLoading,
}: {
  acceptedRiskCount: number
  effectiveSignalCounts: DashboardSignalCounts
  effectiveSummary: ProjectDecisionSummaryPublic | null
  signalLoading: boolean
  summaryLoading: boolean
}): DashboardMetricSummary[] {
  return [
    {
      detail: "Critical findings in scope",
      icon: AlertTriangle,
      label: "Critical Priority",
      tone: "critical",
      value:
        summaryLoading || effectiveSummary === null
          ? "—"
          : String(priorityCount(effectiveSummary, "Critical")),
    },
    {
      detail: "Known CISA KEV findings",
      icon: ShieldAlert,
      label: "KEV Exposed",
      tone: "kev",
      value:
        summaryLoading || effectiveSummary === null
          ? "—"
          : String(effectiveSummary?.kev_hits ?? 0),
    },
    {
      detail: "EPSS ≥70% signals",
      icon: TrendingUp,
      label: "High EPSS",
      tone: "high",
      value: signalLoading ? "—" : String(effectiveSignalCounts.highEpss),
    },
    {
      detail: "Internet-facing criticals",
      icon: Globe2,
      label: "Internet Facing",
      tone: "exposure",
      value: signalLoading
        ? "—"
        : String(effectiveSignalCounts.internetFacingCriticals),
    },
    {
      detail: "Accepted-risk findings",
      icon: ShieldCheck,
      label: "Accepted Risk Due",
      tone: "accepted",
      value:
        summaryLoading || effectiveSummary === null
          ? "—"
          : String(acceptedRiskCount),
    },
  ]
}
