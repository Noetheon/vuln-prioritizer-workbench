import { useMemo, useState } from "react"
import { TooltipProvider } from "@/components/ui/tooltip"
import { Callout } from "@/components/vpw"
import { formatProviderFreshness } from "@/lib/provider-format"
import { DashboardSetupEmptyState } from "./DashboardEmptyState"
import { DashboardContextBar } from "./DashboardContextBar"
import { DashboardMetricStrip } from "./DashboardMetricStrip"
import { DashboardProviderWarning } from "./DashboardProviderWarning"
import { DashboardRemediationSection } from "./DashboardRemediationSection"
import { DashboardRiskReductionPanel } from "./DashboardRiskReductionPanel"
import type {
  QueueFilterState,
  RiskOperationsDashboardProps,
} from "./dashboard-model"
import {
  buildDashboardMetricSummaries,
  providerNeedsRefresh,
  rankedDashboardQueueFindings,
} from "./dashboard-summary-model"

export function RiskOperationsDashboard({
  dashboardError,
  demoWorkspaceEnabled,
  demoWorkspaceError,
  demoWorkspacePending,
  findings,
  findingsError,
  findingsLoading,
  governanceError,
  governanceLoading,
  isManagedDemoWorkspace,
  onLoadDemoWorkspace,
  onRefresh,
  onProjectChange,
  onResetDemoWorkspace,
  projectListLoading,
  projects,
  providerStatus,
  providerStatusError,
  providerStatusLoading,
  riskReduction,
  runsLoading,
  selectedProject,
  selectedProjectId,
  signalCounts,
  signalError,
  signalLoading,
  summaryLoading,
  projectSummary,
}: RiskOperationsDashboardProps) {
  const [filters, setFilters] = useState<QueueFilterState>({
    queueSearch: "",
  })

  const isLoading =
    projectListLoading ||
    summaryLoading ||
    signalLoading ||
    providerStatusLoading ||
    runsLoading ||
    governanceLoading

  const hasProjects = projects.length > 0
  const hasProviderStatus = selectedProject !== null && hasProjects
  const staleProvider = providerNeedsRefresh(hasProviderStatus, providerStatus)

  const freshness = formatProviderFreshness(providerStatus)

  const queueFindings = useMemo(
    () => rankedDashboardQueueFindings(findings, filters.queueSearch),
    [findings, filters.queueSearch],
  )

  const acceptedRiskCount = projectSummary?.counts_by_status?.accepted ?? 0
  const summaryMetrics = useMemo(
    () =>
      buildDashboardMetricSummaries({
        acceptedRiskCount,
        effectiveSignalCounts: signalCounts,
        effectiveSummary: projectSummary,
        signalLoading,
        summaryLoading,
      }),
    [
      acceptedRiskCount,
      signalCounts,
      projectSummary,
      signalLoading,
      summaryLoading,
    ],
  )

  const showEmptyState =
    !isLoading &&
    !hasProviderStatus &&
    !projectListLoading &&
    !projectSummary &&
    !dashboardError &&
    !signalError &&
    !providerStatusError

  const dashboardContent = (
    <div className="min-w-0 flex flex-col gap-4">
      <DashboardContextBar
        demoWorkspaceEnabled={demoWorkspaceEnabled}
        demoWorkspacePending={demoWorkspacePending}
        effectiveProjects={projects}
        effectiveProviderStatus={providerStatus}
        effectiveSelectedProject={selectedProject}
        freshness={freshness}
        isManagedDemoWorkspace={isManagedDemoWorkspace}
        onLoadDemoWorkspace={onLoadDemoWorkspace}
        onProjectChange={onProjectChange}
        onRefresh={onRefresh}
        onResetDemoWorkspace={onResetDemoWorkspace}
        projectListLoading={projectListLoading}
        providerStatusLoading={providerStatusLoading}
        selectedProjectId={selectedProjectId}
      />

      {dashboardError ||
      signalError ||
      providerStatusError ||
      findingsError ||
      demoWorkspaceError ||
      governanceError ? (
        <Callout severity="critical" title="Dashboard unavailable">
          {dashboardError ||
            signalError ||
            providerStatusError ||
            findingsError ||
            demoWorkspaceError ||
            governanceError ||
            "Dashboard is currently unavailable"}
        </Callout>
      ) : null}

      {staleProvider ? <DashboardProviderWarning /> : null}

      {showEmptyState ? (
        <DashboardSetupEmptyState
          demoWorkspaceEnabled={demoWorkspaceEnabled}
          demoWorkspacePending={demoWorkspacePending}
          onLoadDemoWorkspace={onLoadDemoWorkspace}
        />
      ) : (
        <>
          <DashboardRiskReductionPanel
            isLoading={isLoading}
            projectSummary={projectSummary}
            riskReduction={riskReduction}
            selectedProjectId={selectedProjectId}
          />
          <DashboardMetricStrip
            isLoading={isLoading}
            metrics={summaryMetrics}
          />
          <DashboardRemediationSection
            findingsError={findingsError}
            findingsLoading={findingsLoading}
            onQueueSearchChange={(queueSearch) =>
              setFilters((current) => ({
                ...current,
                queueSearch,
              }))
            }
            queueFindings={queueFindings}
            queueSearch={filters.queueSearch}
            selectedProjectId={selectedProjectId}
          />
        </>
      )}
    </div>
  )

  return (
    <TooltipProvider>
      <section
        aria-label="Risk Operations dashboard"
        className="dashboard-analyst-layout flex flex-col gap-4 pb-4"
      >
        <div className="grid gap-4">{dashboardContent}</div>
      </section>
    </TooltipProvider>
  )
}
