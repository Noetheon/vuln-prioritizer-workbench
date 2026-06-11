import { lazy, Suspense, useMemo, useState } from "react"
import { Skeleton } from "@/components/ui/skeleton"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { TooltipProvider } from "@/components/ui/tooltip"
import { Callout } from "@/components/vpw"
import {
  epssBucketChartData,
  findingsByPriorityChartData,
  riskAverageTrendData,
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
  readStoredRiskLayout,
  storeRiskLayout,
  type DashboardRunRange,
  type QueueFilterState,
  type RiskLayoutMode,
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

const DashboardRiskPostureSection = lazy(() =>
  import("./DashboardRiskPostureSection").then((module) => ({
    default: module.DashboardRiskPostureSection,
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
  riskInsights,
  riskInsightsError,
  riskInsightsLoading,
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
  const [riskLayout, setRiskLayout] = useState<RiskLayoutMode>(() =>
    readStoredRiskLayout(),
  )
  const changeRiskLayout = (value: string) => {
    if (value !== "spotlight" && value !== "compact") {
      return
    }
    setRiskLayout(value)
    storeRiskLayout(value)
  }
  const compactRiskLayout = riskLayout === "compact"

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
  const riskTrendItems = useMemo(
    () =>
      riskAverageTrendData(
        riskInsights?.trend ?? [],
        Number.parseInt(filters.selectedRunRange, 10),
      ),
    [riskInsights?.trend, filters.selectedRunRange],
  )
  const mitigationLevers = riskInsights?.mitigation_levers ?? []
  const openRiskTotal =
    riskInsights?.baseline_total_risk_score ??
    (riskInsights?.baseline_average_risk_score !== null &&
    riskInsights?.baseline_average_risk_score !== undefined
      ? Math.round(
          riskInsights.baseline_average_risk_score *
            (riskInsights.baseline_open_finding_count ?? 0),
        )
      : null)

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
          <div className="flex items-center justify-end gap-2 text-xs text-muted-foreground">
            <span id="risk-layout-label">Risk layout</span>
            <ToggleGroup
              aria-labelledby="risk-layout-label"
              onValueChange={changeRiskLayout}
              size="sm"
              type="single"
              value={riskLayout}
              variant="outline"
            >
              <ToggleGroupItem className="px-3" value="spotlight">
                Spotlight
              </ToggleGroupItem>
              <ToggleGroupItem className="px-3" value="compact">
                Compact
              </ToggleGroupItem>
            </ToggleGroup>
          </div>
          {!compactRiskLayout ? (
            <Suspense fallback={<Skeleton className="h-72" />}>
              <DashboardRiskPostureSection
                onRunRangeChange={(value: DashboardRunRange) =>
                  setFilters((current) => ({
                    ...current,
                    selectedRunRange: value,
                  }))
                }
                riskInsights={riskInsights}
                riskInsightsError={riskInsightsError}
                riskInsightsLoading={riskInsightsLoading}
                selectedProjectId={selectedProjectId}
                selectedRunRange={filters.selectedRunRange}
              />
            </Suspense>
          ) : null}
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
            topDriver={
              compactRiskLayout ? (riskInsights?.top_driver ?? null) : null
            }
          />
          <Suspense fallback={<DashboardSignalOverviewFallback />}>
            <DashboardSignalOverview
              epssItems={epssItems}
              governanceLoading={governanceLoading}
              keyTakeaways={signalTakeaways}
              mitigationLevers={mitigationLevers}
              onRunRangeChange={(value: DashboardRunRange) =>
                setFilters((current) => ({
                  ...current,
                  selectedRunRange: value,
                }))
              }
              openRiskTotal={openRiskTotal}
              priorityItems={priorityItems}
              riskInsightsError={riskInsightsError}
              riskInsightsLoading={riskInsightsLoading}
              riskTrendItems={riskTrendItems}
              runsLoading={runsLoading}
              selectedProjectId={selectedProjectId}
              selectedRunRange={filters.selectedRunRange}
              serviceItems={serviceItems}
              showRiskInsights={compactRiskLayout}
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
