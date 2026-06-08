import { lazy, Suspense, useMemo, useState } from "react"
import { TooltipProvider } from "@/components/ui/tooltip"
import { Callout } from "@/components/vpw"
import {
  epssBucketChartData,
  findingsByPriorityChartData,
  runActivityTrendData,
  topServicesByRiskChartData,
} from "@/lib/chart-data"
import { formatProviderFreshness } from "@/lib/provider-format"
import {
  DashboardDemoBanner,
  DashboardSetupEmptyState,
} from "./DashboardEmptyState"
import { DashboardContextBar } from "./DashboardContextBar"
import { DashboardDetailRail } from "./DashboardDetailRail"
import { DashboardMetricStrip } from "./DashboardMetricStrip"
import { DashboardProviderWarning } from "./DashboardProviderWarning"
import { DashboardRemediationSection } from "./DashboardRemediationSection"
import { DashboardSignalOverviewFallback } from "./DashboardSignalOverviewFallback"
import {
  latestRunFacts,
  type DashboardRunRange,
  type QueueFilterState,
  type RiskOperationsDashboardProps,
} from "./dashboard-model"
import {
  buildDashboardMetricSummaries,
  buildDashboardSignalTakeaways,
  providerNeedsRefresh,
  rankedDashboardQueueFindings,
} from "./dashboard-summary-model"

const DashboardSignalOverview = lazy(() =>
  import("./DashboardSignalOverview").then((module) => ({
    default: module.DashboardSignalOverview,
  })),
)

export function RiskOperationsDashboard({
  dashboardError,
  demoWorkspaceEnabled,
  demoWorkspaceError,
  demoWorkspacePending,
  epssBuckets,
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
  projectRuns,
  projects,
  providerStatus,
  providerStatusError,
  providerStatusLoading,
  runsLoading,
  selectedProject,
  selectedProjectId,
  signalCounts,
  signalError,
  signalLoading,
  summaryLoading,
  topServiceRows,
  topServiceSource,
  projectSummary,
}: RiskOperationsDashboardProps) {
  const [filters, setFilters] = useState<QueueFilterState>({
    queueSearch: "",
    selectedRunRange: "10",
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

  const priorityItems = findingsByPriorityChartData(projectSummary)
  const serviceItems = topServicesByRiskChartData(topServiceRows)
  const trendItems = useMemo(
    () =>
      runActivityTrendData(
        projectRuns,
        Number.parseInt(filters.selectedRunRange, 10),
      ),
    [projectRuns, filters.selectedRunRange],
  )

  const epssItems = useMemo(() => {
    if (epssBuckets.length > 0) return epssBuckets
    return epssBucketChartData(signalCounts.epssBuckets)
  }, [epssBuckets, signalCounts.epssBuckets])

  const queueFindings = useMemo(
    () => rankedDashboardQueueFindings(findings, filters.queueSearch),
    [findings, filters.queueSearch],
  )

  const latestRun = projectRuns[0] ?? null
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

  const latestRunFactsRows = latestRunFacts(projectRuns)
  const dataQualityWarnings = providerStatus?.warnings ?? []
  const dataQualityError = providerStatus?.last_error ?? null
  const topServiceLabel = serviceItems[0]?.label ?? null
  const signalTakeaways = buildDashboardSignalTakeaways({
    acceptedRiskCount,
    effectiveSignalCounts: signalCounts,
    effectiveSummary: projectSummary,
    topServiceLabel,
  })

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

      {isManagedDemoWorkspace ? (
        <DashboardDemoBanner
          demoWorkspaceEnabled={demoWorkspaceEnabled}
          demoWorkspacePending={demoWorkspacePending}
          isManagedDemoWorkspace={isManagedDemoWorkspace}
          onLoadDemoWorkspace={onLoadDemoWorkspace}
          onResetDemoWorkspace={onResetDemoWorkspace}
        />
      ) : null}

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
          <Suspense fallback={<DashboardSignalOverviewFallback />}>
            <DashboardSignalOverview
              epssItems={epssItems}
              governanceLoading={governanceLoading}
              keyTakeaways={signalTakeaways}
              onRunRangeChange={(value: DashboardRunRange) =>
                setFilters((current) => ({
                  ...current,
                  selectedRunRange: value,
                }))
              }
              priorityItems={priorityItems}
              runsLoading={runsLoading}
              selectedProjectId={selectedProjectId}
              selectedRunRange={filters.selectedRunRange}
              serviceItems={serviceItems}
              summaryLoading={summaryLoading}
              topServiceSource={topServiceSource}
              trendItems={trendItems}
            />
          </Suspense>
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
        <div
          className={
            showEmptyState ? "grid gap-4" : "dashboard-command-grid grid gap-4"
          }
        >
          {dashboardContent}
          {!showEmptyState ? (
            <DashboardDetailRail
              dataQualityError={dataQualityError}
              dataQualityWarnings={dataQualityWarnings}
              effectiveProviderStatus={providerStatus}
              effectiveRuns={projectRuns}
              effectiveSummary={projectSummary}
              freshness={freshness}
              latestRun={latestRun}
              latestRunFactsRows={latestRunFactsRows}
              providerStatusLoading={providerStatusLoading}
              selectedProjectId={selectedProjectId}
              staleProvider={staleProvider}
            />
          ) : null}
        </div>
      </section>
    </TooltipProvider>
  )
}
