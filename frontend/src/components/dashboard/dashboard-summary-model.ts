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
  ProjectRiskKpisPublic,
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

/** Tiles count open work (open, in review, remediating), not closed findings. */
export function buildDashboardMetricSummaries({
  acceptedRiskCount,
  effectiveSignalCounts,
  effectiveSummary,
  kpis = null,
  signalLoading,
  summaryLoading,
}: {
  acceptedRiskCount: number
  effectiveSignalCounts: DashboardSignalCounts
  effectiveSummary: ProjectDecisionSummaryPublic | null
  kpis?: ProjectRiskKpisPublic | null
  signalLoading: boolean
  summaryLoading: boolean
}): DashboardMetricSummary[] {
  const summaryMissing = summaryLoading || effectiveSummary === null
  return [
    {
      detail: "Critical findings still open",
      icon: AlertTriangle,
      label: "Open Critical",
      tone: "critical",
      value: summaryMissing
        ? "—"
        : String(kpis?.open_critical ?? priorityCount(effectiveSummary, "Critical")),
    },
    {
      detail: "Known exploited (CISA KEV), still open",
      icon: ShieldAlert,
      label: "Open KEV",
      tone: "kev",
      value: summaryMissing
        ? "—"
        : String(kpis?.open_kev ?? effectiveSummary?.kev_hits ?? 0),
    },
    {
      detail: "Open findings with EPSS ≥70%",
      icon: TrendingUp,
      label: "High EPSS",
      tone: "high",
      value: signalLoading ? "—" : String(effectiveSignalCounts.highEpss),
    },
    {
      detail: "Open internet-facing criticals",
      icon: Globe2,
      label: "Internet Facing",
      tone: "exposure",
      value: signalLoading
        ? "—"
        : String(effectiveSignalCounts.internetFacingCriticals),
    },
    {
      detail: "Accepted findings, not open work",
      icon: ShieldCheck,
      label: "Accepted Risk",
      tone: "accepted",
      value: summaryMissing
        ? "—"
        : String(kpis?.accepted_findings ?? acceptedRiskCount),
    },
  ]
}
