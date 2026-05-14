import type { LucideIcon } from "lucide-react"
import type { ReactNode } from "react"
import type {
  AnalysisRunPublic,
  FindingPublic,
  GovernanceRollupPublic,
  ProjectDecisionSummaryPublic,
  ProjectPublic,
  ProviderStatusPublic,
} from "@/api-client"
import type { ChartDatum, EpssBucketCounts } from "@/lib/chart-data"
import { runStatusLabel, runStatusTone } from "@/lib/risk-format"
import { optionalText } from "@/lib/ui-copy"

export type DashboardSignalCounts = {
  highEpss: number
  internetFacingCriticals: number
  epssBuckets: EpssBucketCounts
}

export type DashboardRunRange = "10" | "30" | "all"

export type RiskOperationsDashboardProps = {
  dashboardError?: string
  demoWorkspaceEnabled: boolean
  demoWorkspaceError: string
  demoWorkspacePending: boolean
  epssBuckets: readonly ChartDatum[]
  findings: readonly FindingPublic[]
  findingsError: string
  findingsLoading: boolean
  governanceError: string
  governanceLoading: boolean
  onRefresh: () => void
  onLoadDemoWorkspace: () => void
  onResetDemoWorkspace: () => void
  onProjectChange: (projectId: string) => void
  projectListLoading: boolean
  projectRuns: readonly AnalysisRunPublic[]
  projects: readonly ProjectPublic[]
  providerStatus: ProviderStatusPublic | null
  providerStatusError: string
  providerStatusLoading: boolean
  runsLoading: boolean
  selectedProject: ProjectPublic | null
  selectedProjectId: string
  signalCounts: DashboardSignalCounts
  signalError: string
  signalLoading: boolean
  summaryLoading: boolean
  topServiceRows: readonly GovernanceRollupPublic[]
  topServiceSource: "assets" | "services"
  projectSummary: ProjectDecisionSummaryPublic | null
  isManagedDemoWorkspace: boolean
}

export type QueueFilterState = {
  queueSearch: string
  selectedRunRange: DashboardRunRange
}

export type DashboardMetricSummary = {
  detail: ReactNode
  icon: LucideIcon
  label: string
  tone: string
  value: ReactNode
}

export type DashboardRunFact = {
  id: string
  startedAt: string
  status: string
  tone: ReturnType<typeof runStatusTone>
}

export function findingWhyNow(finding: FindingPublic) {
  return (
    optionalText(finding.rationale) ??
    optionalText(finding.recommended_action) ??
    "No explanation was captured yet."
  )
}

export function formatDateTime(value: string | null | undefined) {
  if (!value) return "Pending"
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return "Invalid"
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date)
}

export function latestRunLabel(run: AnalysisRunPublic | null) {
  if (!run) return "No runs yet"
  const statusLabel = runStatusLabel(run.status ?? "pending")
  return run.started_at
    ? `${statusLabel} · ${formatDateTime(run.started_at)}`
    : statusLabel
}

export function latestRunFacts(
  runs: readonly AnalysisRunPublic[],
): DashboardRunFact[] {
  return runs.slice(0, 4).map((run) => ({
    id: run.id,
    startedAt: formatDateTime(run.started_at),
    status: runStatusLabel(run.status ?? "pending"),
    tone: runStatusTone(run.status ?? "pending"),
  }))
}
