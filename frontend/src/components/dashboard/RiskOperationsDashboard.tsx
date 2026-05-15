import {
  AlertCircle,
  AlertTriangle,
  Globe2,
  ShieldAlert,
  TrendingUp,
} from "lucide-react"
import { lazy, Suspense, useMemo, useState } from "react"
import { Skeleton } from "@/components/ui/skeleton"
import { TooltipProvider } from "@/components/ui/tooltip"
import {
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import {
  epssBucketChartData,
  findingsByPriorityChartData,
  priorityCount,
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
import { DashboardRemediationSection } from "./DashboardRemediationSection"
import { DashboardSidePanel } from "./DashboardSidePanel"
import {
  latestRunFacts,
  type DashboardMetricSummary,
  type DashboardRunRange,
  type QueueFilterState,
  type RiskOperationsDashboardProps,
} from "./dashboard-model"

const DashboardSignalOverview = lazy(() =>
  import("./DashboardSignalOverview").then((module) => ({
    default: module.DashboardSignalOverview,
  })),
)

function DashboardSignalOverviewFallback() {
  return (
    <VpwSurface aria-label="Signal Overview loading" className="gap-4 py-4">
      <VpwSurfaceHeader>
        <VpwSurfaceTitle>Signal Overview</VpwSurfaceTitle>
        <VpwSurfaceDescription>
          Signal concentration, service risk, and trend direction for executive
          review.
        </VpwSurfaceDescription>
      </VpwSurfaceHeader>
      <VpwSurfaceBody>
        <div
          aria-label="Loading Signal Overview charts"
          className="flex flex-col gap-4"
          role="status"
        >
          <div className="flex flex-wrap gap-2">
            <Skeleton className="h-8 w-36" />
            <Skeleton className="h-8 w-32" />
            <Skeleton className="h-8 w-28" />
            <Skeleton className="h-8 w-24" />
          </div>
          <Skeleton className="h-64 w-full" />
        </div>
      </VpwSurfaceBody>
    </VpwSurface>
  )
}

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
  const staleProvider =
    hasProviderStatus &&
    effectiveProviderStatus !== null &&
    (effectiveProviderStatus.status !== "ok" ||
      Boolean(effectiveProviderStatus.last_error) ||
      (effectiveProviderStatus.warnings?.length ?? 0) > 0)

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

  const queueFindings = useMemo(() => {
    const ranked = [...effectiveFindings].sort(
      (a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0),
    )
    const query = filters.queueSearch.trim().toLowerCase()
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
  }, [effectiveFindings, filters.queueSearch])

  const latestRun = effectiveRuns[0] ?? null
  const summaryCards = useMemo<DashboardMetricSummary[]>(
    () => [
      {
        detail: "Critical-priority findings in scope",
        icon: AlertTriangle,
        label: "Critical Priority",
        tone: "critical",
        value:
          (!isDemoMode && summaryLoading) || effectiveSummary === null
            ? "—"
            : String(priorityCount(effectiveSummary, "Critical")),
      },
      {
        detail: "Known CISA KEV findings in scope",
        icon: ShieldAlert,
        label: "KEV Exposed",
        tone: "kev",
        value:
          (!isDemoMode && summaryLoading) || effectiveSummary === null
            ? "—"
            : String(effectiveSummary?.kev_hits ?? 0),
      },
      {
        detail: "High-confidence EPSS signals (≥70%)",
        icon: TrendingUp,
        label: "High EPSS",
        tone: "high",
        value:
          !isDemoMode && signalLoading
            ? "—"
            : String(effectiveSignalCounts.highEpss),
      },
      {
        detail: "Critical internet-facing findings",
        icon: Globe2,
        label: "Internet Facing",
        tone: "exposure",
        value:
          !isDemoMode && signalLoading
            ? "—"
            : String(effectiveSignalCounts.internetFacingCriticals),
      },
    ],
    [
      isDemoMode,
      effectiveSummary,
      effectiveSignalCounts.highEpss,
      effectiveSignalCounts.internetFacingCriticals,
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
  const criticalCount =
    effectiveSummary === null ? 0 : priorityCount(effectiveSummary, "Critical")
  const kevCount = effectiveSummary?.kev_hits ?? 0
  const internetFacingCount = effectiveSignalCounts.internetFacingCriticals
  const topServiceLabel = serviceItems[0]?.label ?? null
  const acceptedRiskCount = effectiveFindings.filter(
    (finding) => finding.status === "accepted",
  ).length
  const signalTakeaways = [
    `${criticalCount} critical findings demand immediate action.`,
    kevCount > 0
      ? `${kevCount} known-exploited KEV findings are active prioritization signals.`
      : "No known-exploited KEV findings are currently in scope.",
    internetFacingCount > 0
      ? `${internetFacingCount} internet-facing critical findings drive near-term risk.`
      : "No internet-facing critical findings are currently driving the queue.",
    acceptedRiskCount > 0
      ? `${acceptedRiskCount} accepted-risk records should stay on review cadence.`
      : topServiceLabel
        ? `${topServiceLabel} is the highest-risk service concentration.`
        : "Service concentration will appear after ownership data is imported.",
  ]

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

      {staleProvider ? (
        <VpwSurface className="border-[var(--vpw-amber)] bg-[var(--vpw-bg-warning)]">
          <VpwSurfaceHeader className="py-3">
            <div className="flex items-center gap-2">
              <AlertCircle
                className="size-4 text-[var(--vpw-amber)]"
                aria-hidden="true"
              />
              <VpwSurfaceTitle className="text-sm text-[var(--vpw-text-primary)]">
                Provider data needs refresh
              </VpwSurfaceTitle>
            </div>
            <VpwSurfaceDescription className="text-xs text-[var(--vpw-text-secondary)]">
              Freshness is stale or partially degraded. Remediation priority
              remains functional, but evidence may not be fully current.
            </VpwSurfaceDescription>
          </VpwSurfaceHeader>
        </VpwSurface>
      ) : null}

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
            showEmptyState
              ? "grid gap-4"
              : "dashboard-command-grid grid gap-4 2xl:grid-cols-[minmax(0,1fr)_22rem]"
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
