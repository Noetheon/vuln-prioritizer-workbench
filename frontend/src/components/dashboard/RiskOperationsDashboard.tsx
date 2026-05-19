import { lazy, Suspense, useMemo, useState } from "react"
import { TooltipProvider } from "@/components/ui/tooltip"
import {
  epssBucketChartData,
  findingsByPriorityChartData,
  runActivityTrendData,
  topServicesByRiskChartData,
} from "@/lib/chart-data"
import {
  DEMO_FINDINGS,
  DEMO_PROJECT,
  DEMO_PROVIDER_STATUS,
  DEMO_RUNS,
  DEMO_SIGNAL_COUNTS,
  DEMO_SUMMARY,
  DEMO_TOP_SERVICES,
} from "@/lib/demo-data"
import { formatProviderFreshness } from "@/lib/provider-format"
import { DEMO_MODE_ENABLED } from "@/lib/runtime-config"
import { ErrorState } from "../states"
import {
  DashboardDemoBanner,
  DashboardSetupEmptyState,
} from "./DashboardEmptyState"
import { DashboardHero } from "./DashboardHero"
import { DashboardMetricGrid } from "./DashboardMetricGrid"
import { DashboardProviderWarning } from "./DashboardProviderWarning"
import { DashboardRemediationSection } from "./DashboardRemediationSection"
import { DashboardSidePanel } from "./DashboardSidePanel"
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

  const isDemoMode =
    DEMO_MODE_ENABLED &&
    !projectListLoading &&
    projects.length === 0 &&
    !dashboardError

  const effectiveProjects = isDemoMode ? [DEMO_PROJECT] : projects
  const effectiveSelectedProject = isDemoMode ? DEMO_PROJECT : selectedProject
  const effectiveSummary = isDemoMode ? DEMO_SUMMARY : projectSummary
  const effectiveSignalCounts = isDemoMode ? DEMO_SIGNAL_COUNTS : signalCounts
  const effectiveFindings = isDemoMode ? DEMO_FINDINGS : findings
  const effectiveRuns = isDemoMode ? DEMO_RUNS : projectRuns
  const effectiveTopServices = isDemoMode ? DEMO_TOP_SERVICES : topServiceRows
  const effectiveProviderStatus = isDemoMode
    ? DEMO_PROVIDER_STATUS
    : providerStatus

  const isLoading =
    !isDemoMode &&
    (projectListLoading ||
      summaryLoading ||
      signalLoading ||
      providerStatusLoading ||
      runsLoading ||
      governanceLoading)

  const hasProjects = effectiveProjects.length > 0
  const hasProviderStatus = effectiveSelectedProject !== null && hasProjects
  const staleProvider = providerNeedsRefresh(
    hasProviderStatus,
    effectiveProviderStatus,
  )

  const freshness = formatProviderFreshness(effectiveProviderStatus)

  const priorityItems = findingsByPriorityChartData(effectiveSummary)
  const serviceItems = topServicesByRiskChartData(effectiveTopServices)
  const trendItems = useMemo(
    () =>
      runActivityTrendData(
        effectiveRuns,
        filters.selectedRunRange === "all"
          ? effectiveRuns.length
          : Number.parseInt(filters.selectedRunRange, 10),
      ),
    [effectiveRuns, filters.selectedRunRange],
  )

  const epssItems = useMemo(() => {
    if (!isDemoMode && epssBuckets.length > 0) return epssBuckets
    return epssBucketChartData(effectiveSignalCounts.epssBuckets)
  }, [isDemoMode, epssBuckets, effectiveSignalCounts.epssBuckets])

  const queueFindings = useMemo(
    () => rankedDashboardQueueFindings(effectiveFindings, filters.queueSearch),
    [effectiveFindings, filters.queueSearch],
  )

  const latestRun = effectiveRuns[0] ?? null
  const acceptedRiskCount = effectiveSummary?.counts_by_status?.accepted ?? 0
  const summaryCards = useMemo(
    () =>
      buildDashboardMetricSummaries({
        acceptedRiskCount,
        effectiveSignalCounts,
        effectiveSummary,
        isDemoMode,
        signalLoading,
        summaryLoading,
      }),
    [
      acceptedRiskCount,
      effectiveSignalCounts,
      effectiveSummary,
      isDemoMode,
      signalLoading,
      summaryLoading,
    ],
  )

  const showEmptyState =
    !isDemoMode &&
    !isLoading &&
    !hasProviderStatus &&
    !projectListLoading &&
    !effectiveSummary &&
    !dashboardError &&
    !signalError &&
    !providerStatusError

  const latestRunFactsRows = latestRunFacts(effectiveRuns)
  const dataQualityWarnings = effectiveProviderStatus?.warnings ?? []
  const dataQualityError = effectiveProviderStatus?.last_error ?? null
  const topServiceLabel = serviceItems[0]?.label ?? null
  const signalTakeaways = buildDashboardSignalTakeaways({
    acceptedRiskCount,
    effectiveSignalCounts,
    effectiveSummary,
    topServiceLabel,
  })

  const dashboardContent = (
    <div className="min-w-0 flex flex-col gap-4">
      <DashboardHero
        demoWorkspaceEnabled={demoWorkspaceEnabled}
        demoWorkspacePending={demoWorkspacePending}
        effectiveProjects={effectiveProjects}
        effectiveProviderStatus={effectiveProviderStatus}
        effectiveSelectedProject={effectiveSelectedProject}
        freshness={freshness}
        isManagedDemoWorkspace={isManagedDemoWorkspace}
        isDemoMode={isDemoMode}
        onLoadDemoWorkspace={onLoadDemoWorkspace}
        onProjectChange={onProjectChange}
        onRefresh={onRefresh}
        onResetDemoWorkspace={onResetDemoWorkspace}
        projectListLoading={projectListLoading}
        providerStatusLoading={providerStatusLoading}
        selectedProjectId={selectedProjectId}
      />

      {isDemoMode || isManagedDemoWorkspace ? (
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
        <ErrorState
          message={
            dashboardError ||
            signalError ||
            providerStatusError ||
            findingsError ||
            demoWorkspaceError ||
            governanceError ||
            "Dashboard is currently unavailable"
          }
        />
      ) : null}

      {staleProvider ? <DashboardProviderWarning /> : null}

      {showEmptyState ? (
        <DashboardSetupEmptyState
          demoWorkspaceEnabled={demoWorkspaceEnabled}
          demoWorkspacePending={demoWorkspacePending}
          onLoadDemoWorkspace={onLoadDemoWorkspace}
          onResetDemoWorkspace={onResetDemoWorkspace}
        />
      ) : (
        <>
          <DashboardMetricGrid cards={summaryCards} isLoading={isLoading} />
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
              selectedProjectId={isDemoMode ? "" : selectedProjectId}
              selectedRunRange={filters.selectedRunRange}
              serviceItems={serviceItems}
              summaryLoading={summaryLoading}
              topServiceSource={topServiceSource}
              trendItems={trendItems}
            />
          </Suspense>
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
            selectedProjectId={isDemoMode ? "" : selectedProjectId}
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
        <div
          className={
            showEmptyState ? "grid gap-4" : "dashboard-command-grid grid gap-4"
          }
        >
          {dashboardContent}
          {!showEmptyState ? (
            <DashboardSidePanel
              dataQualityError={dataQualityError}
              dataQualityWarnings={dataQualityWarnings}
              effectiveProviderStatus={effectiveProviderStatus}
              effectiveRuns={effectiveRuns}
              effectiveSummary={effectiveSummary}
              freshness={freshness}
              latestRun={latestRun}
              latestRunFactsRows={latestRunFactsRows}
              providerStatusLoading={providerStatusLoading}
              selectedProjectId={isDemoMode ? "" : selectedProjectId}
              staleProvider={staleProvider}
            />
          ) : null}
        </div>
      </section>
    </TooltipProvider>
  )
}
