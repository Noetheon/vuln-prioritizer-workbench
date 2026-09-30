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
import { rankedRemediationQueue } from "@/lib/finding-queue-labels"
import { providerDataState } from "@/lib/provider-format"
import type {
  DashboardMetricSummary,
  DashboardSignalCounts,
} from "./dashboard-model"

export function providerNeedsRefresh(
  hasProviderStatus: boolean,
  providerStatus: ProviderStatusPublic | null,
) {
  if (!hasProviderStatus || providerStatus === null) {
    return false
  }
  switch (providerDataState(providerStatus)) {
    case "stale":
    case "degraded":
      return true
    case "fresh":
      return (providerStatus.warnings?.length ?? 0) > 0
    default:
      // Nothing fetched yet is not a fault: the first import fetches data.
      return false
  }
}

export function providerRefreshDetail(providerStatus: ProviderStatusPublic | null) {
  return (
    providerStatus?.last_error ??
    providerStatus?.warnings?.[0] ??
    "Provider data is stale or partially degraded."
  )
}

export function rankedDashboardQueueFindings(
  findings: readonly FindingPublic[],
  queueSearch: string,
) {
  return rankedRemediationQueue(findings, queueSearch)
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
