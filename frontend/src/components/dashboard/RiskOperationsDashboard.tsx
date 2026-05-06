import {
  AlertCircle,
  AlertTriangle,
  BellRing,
  Database,
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
import { ErrorState } from "../states"
import { DashboardDemoBanner, DashboardSetupEmptyState } from "./DashboardEmptyState"
import { DashboardHero } from "./DashboardHero"
import { DashboardMetricGrid } from "./DashboardMetricGrid"
import { DashboardRemediationSection } from "./DashboardRemediationSection"
import { DashboardSidePanel } from "./DashboardSidePanel"
import {
  latestRunFacts,
  latestRunLabel,
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
          className="space-y-4"
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
  epssBuckets,
  findings,
  findingsError,
  findingsLoading,
  governanceError,
  governanceLoading,
  onRefresh,
  onProjectChange,
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

  // ── Demo preview mode ────────────────────────────────────────────────────
  // Active only when no real project is connected. A labeled banner is shown.
  const isDemoMode =
    !projectListLoading && projects.length === 0 && !dashboardError

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
  const freshnessCard = useMemo<DashboardMetricSummary[]>(
    () => [
      {
        detail: "Critical-priority active findings",
        icon: AlertTriangle,
        label: "Critical Open",
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
          (!isDemoMode && summaryLoading) || effectiveSummary === null
            ? "—"
            : String(effectiveSignalCounts.highEpss),
      },
      {
        detail: "High-priority active findings",
        icon: AlertCircle,
        label: "High Open",
        tone: "high",
        value:
          (!isDemoMode && summaryLoading) || effectiveSummary === null
            ? "—"
            : String(priorityCount(effectiveSummary, "High")),
      },
      {
        detail: freshness.detail,
        icon: Database,
        label: "Provider Freshness",
        tone: freshness.tone,
        value: <span className="text-sm font-semibold">{freshness.value}</span>,
      },
      {
        detail: latestRun ? latestRunLabel(latestRun) : "No runs available",
        icon: BellRing,
        label: "Latest Analysis",
        tone: "run",
        value: (
          <span className="text-sm font-semibold">
            {effectiveSummary?.latest_run_id
              ? `Run ${effectiveSummary.latest_run_id.slice(0, 8)}`
              : "Pending"}
          </span>
        ),
      },
    ],
    [
      isDemoMode,
      effectiveSummary,
      effectiveSignalCounts.highEpss,
      latestRun,
      summaryLoading,
      freshness,
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

  return (
    <TooltipProvider>
      <section
        aria-label="Risk Operations dashboard"
        className="space-y-4 pb-4"
      >
        <DashboardHero
          effectiveProjects={effectiveProjects}
          effectiveProviderStatus={effectiveProviderStatus}
          effectiveSelectedProject={effectiveSelectedProject}
          freshness={freshness}
          isDemoMode={isDemoMode}
          onProjectChange={onProjectChange}
          onRefresh={onRefresh}
          projectListLoading={projectListLoading}
          providerStatusLoading={providerStatusLoading}
          selectedProjectId={selectedProjectId}
        />

        {isDemoMode ? <DashboardDemoBanner /> : null}

        {dashboardError ||
        signalError ||
        providerStatusError ||
        findingsError ||
        governanceError ? (
          <ErrorState
            message={
              dashboardError ||
              signalError ||
              providerStatusError ||
              findingsError ||
              governanceError ||
              "Dashboard is currently unavailable"
            }
          />
        ) : null}

        {staleProvider ? (
          <VpwSurface className="border-amber-300 bg-amber-50/70 dark:bg-amber-950/35">
            <VpwSurfaceHeader className="py-3">
              <div className="flex items-center gap-2">
                <AlertCircle className="size-4 text-amber-600 dark:text-amber-400" />
                <VpwSurfaceTitle className="text-sm text-amber-800 dark:text-amber-300">
                  Provider data needs refresh
                </VpwSurfaceTitle>
              </div>
              <VpwSurfaceDescription className="text-xs text-amber-700/80 dark:text-amber-400/80">
                Freshness is stale or partially degraded. Remediation priority
                remains functional, but evidence may not be fully current.
              </VpwSurfaceDescription>
            </VpwSurfaceHeader>
          </VpwSurface>
        ) : null}

        {showEmptyState ? <DashboardSetupEmptyState /> : null}

        <div className="grid gap-4 lg:grid-cols-[1fr_196px]">
          <div className="min-w-0 space-y-4">
            <DashboardMetricGrid cards={freshnessCard} isLoading={isLoading} />
            <Suspense fallback={<DashboardSignalOverviewFallback />}>
              <DashboardSignalOverview
                epssItems={epssItems}
                governanceLoading={governanceLoading}
                onRunRangeChange={(value: DashboardRunRange) =>
                  setFilters((current) => ({
                    ...current,
                    selectedRunRange: value,
                  }))
                }
                priorityItems={priorityItems}
                runsLoading={runsLoading}
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
            />
          </div>

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
            staleProvider={staleProvider}
          />
        </div>
      </section>
    </TooltipProvider>
  )
}
