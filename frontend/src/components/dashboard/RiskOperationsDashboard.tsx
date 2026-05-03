import { Link } from "@tanstack/react-router"
import {
  AlertCircle,
  AlertTriangle,
  BellRing,
  CheckCircle2,
  Database,
  Eye,
  Import,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
} from "lucide-react"
import { useMemo, useState } from "react"
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  XAxis,
  YAxis,
} from "recharts"
import type {
  AnalysisRunPublic,
  FindingPublic,
  GovernanceRollupPublic,
  ProjectDecisionSummaryPublic,
  ProjectPublic,
  ProviderStatusPublic,
} from "@/api-client"
import { ChartCard } from "@/components/charts/ChartCard"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import {
  type ChartDatum,
  type EpssBucketCounts,
  epssBucketChartData,
  findingsByPriorityChartData,
  runActivityTrendData,
  topServicesByRiskChartData,
} from "@/lib/chart-data"
import {
  DEMO_FINDINGS,
  DEMO_PROJECT,
  DEMO_PROJECT_ID,
  DEMO_PROVIDER_STATUS,
  DEMO_RUNS,
  DEMO_SIGNAL_COUNTS,
  DEMO_SUMMARY,
  DEMO_TOP_SERVICES,
} from "@/lib/demo-data"
import { formatProviderFreshness } from "@/lib/provider-format"
import { runStatusLabel, runStatusTone } from "@/lib/risk-format"
import { optionalText } from "@/lib/ui-copy"
import { MetricCard } from "../risk/MetricCard"
import { ProviderStatusBadge } from "../risk/ProviderStatusBadge"
import { RiskBadge } from "../risk/RiskBadge"
import { SeverityBadge } from "../risk/SeverityBadge"
import { EmptyState, ErrorState } from "../states"

type DashboardSignalCounts = {
  highEpss: number
  internetFacingCriticals: number
  epssBuckets: EpssBucketCounts
}

type DashboardRunRange = "10" | "30" | "all"

type RiskOperationsDashboardProps = {
  dashboardError?: string
  epssBuckets: readonly ChartDatum[]
  findings: readonly FindingPublic[]
  findingsError: string
  findingsLoading: boolean
  governanceError: string
  governanceLoading: boolean
  onRefresh: () => void
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
}

type QueueFilterState = {
  queueSearch: string
  selectedRunRange: DashboardRunRange
}

function findingWhyNow(finding: FindingPublic) {
  return (
    optionalText(finding.rationale) ??
    optionalText(finding.recommended_action) ??
    "No explanation was captured yet."
  )
}

function formatDateTime(value: string | null | undefined) {
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

function latestRunLabel(run: AnalysisRunPublic | null) {
  if (!run) return "No runs yet"
  const statusLabel = runStatusLabel(run.status ?? "pending")
  return run.started_at
    ? `${statusLabel} · ${formatDateTime(run.started_at)}`
    : statusLabel
}

function latestRunFacts(runs: readonly AnalysisRunPublic[]) {
  return runs.slice(0, 4).map((run) => ({
    id: run.id,
    startedAt: formatDateTime(run.started_at),
    status: runStatusLabel(run.status ?? "pending"),
    tone: runStatusTone(run.status ?? "pending"),
  }))
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
  const freshnessCard = useMemo(
    () => [
      {
        detail: "Critical-priority active findings",
        icon: AlertTriangle,
        label: "Critical Open",
        tone: "critical" as const,
        value:
          (!isDemoMode && summaryLoading) || effectiveSummary === null
            ? "—"
            : String(effectiveSummary?.counts_by_priority?.critical ?? 0),
      },
      {
        detail: "Known CISA KEV findings in scope",
        icon: ShieldAlert,
        label: "KEV Exposed",
        tone: "kev" as const,
        value:
          (!isDemoMode && summaryLoading) || effectiveSummary === null
            ? "—"
            : String(effectiveSummary?.kev_hits ?? 0),
      },
      {
        detail: "High-confidence EPSS signals (≥70%)",
        icon: TrendingUp,
        label: "High EPSS",
        tone: "high" as const,
        value:
          (!isDemoMode && summaryLoading) || effectiveSummary === null
            ? "—"
            : String(effectiveSignalCounts.highEpss),
      },
      {
        detail: "High-priority active findings",
        icon: AlertCircle,
        label: "High Open",
        tone: "high" as const,
        value:
          (!isDemoMode && summaryLoading) || effectiveSummary === null
            ? "—"
            : String(effectiveSummary?.counts_by_priority?.high ?? 0),
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
        tone: "run" as const,
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
        {/* ── HERO ── */}
        <div className="relative overflow-hidden rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-strong)] bg-[var(--vpw-navy)] px-5 py-4 shadow-[var(--vpw-shadow-2)]">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-0 opacity-[0.04]"
            style={{
              backgroundImage:
                "radial-gradient(circle at 1px 1px, white 1px, transparent 0)",
              backgroundSize: "24px 24px",
            }}
          />
          <div className="relative flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <div className="flex items-center gap-2 mb-1.5">
                <ShieldCheck
                  aria-hidden="true"
                  className="size-3.5 text-amber-400"
                />
                <span className="text-[10px] font-bold uppercase tracking-widest text-amber-400">
                  Security Operations
                </span>
              </div>
              <p className="truncate text-base font-semibold text-white">
                {effectiveSelectedProject
                  ? effectiveSelectedProject.name
                  : "No project selected"}
              </p>
              <p className="mt-0.5 text-xs text-slate-400">
                Prioritized vulnerability operations for this project
              </p>
            </div>

            <div className="flex shrink-0 flex-wrap items-center gap-2">
              <Select
                disabled={
                  isDemoMode ||
                  projectListLoading ||
                  effectiveProjects.length === 0
                }
                onValueChange={(value) => {
                  if (value !== "none") onProjectChange(value)
                }}
                value={
                  isDemoMode ? DEMO_PROJECT_ID : selectedProjectId || "none"
                }
              >
                <SelectTrigger className="w-44 border-white/20 bg-white/10 text-white hover:bg-white/20 focus:ring-white/30">
                  <SelectValue placeholder="Select project" />
                </SelectTrigger>
                <SelectContent>
                  {effectiveProjects.length === 0 ? (
                    <SelectItem value="none">No projects yet</SelectItem>
                  ) : (
                    effectiveProjects.map((project) => (
                      <SelectItem key={project.id} value={project.id}>
                        {project.name}
                      </SelectItem>
                    ))
                  )}
                </SelectContent>
              </Select>

              <Button
                asChild
                className="bg-white font-semibold text-slate-900 hover:bg-slate-100"
              >
                <Link to="/imports">
                  <Import aria-hidden="true" className="size-4" />
                  Import findings
                </Link>
              </Button>
              <Button
                asChild
                className="border border-white/25 bg-transparent text-white hover:bg-white/10 hover:text-white"
                variant="ghost"
              >
                <Link to="/reports">
                  <BellRing aria-hidden="true" className="size-4" />
                  Generate evidence
                </Link>
              </Button>
              <Button
                aria-label="Refresh dashboard"
                className="text-white/70 hover:bg-white/10 hover:text-white"
                onClick={onRefresh}
                size="icon"
                type="button"
                variant="ghost"
              >
                <RefreshCw className="size-4" />
              </Button>
            </div>
          </div>

          {/* Provider freshness strip */}
          <div className="relative mt-3 flex flex-wrap items-center gap-3 border-t border-white/10 pt-3">
            <ProviderStatusBadge
              status={
                effectiveProviderStatus?.status ??
                (providerStatusLoading ? "loading" : "unknown")
              }
            />
            <span className="text-sm text-slate-300">{freshness.value}</span>
            <span className="text-slate-600">·</span>
            <span className="text-xs text-slate-400">{freshness.detail}</span>
          </div>
        </div>

        {/* ── DEMO BANNER ── */}
        {isDemoMode ? (
          <div className="flex items-center gap-3 rounded-lg border border-amber-200 bg-amber-50 px-4 py-2 text-sm text-amber-800">
            <ShieldCheck
              aria-hidden="true"
              className="size-4 shrink-0 text-amber-600"
            />
            <p>
              <strong className="font-semibold">Demo preview</strong> — sample
              data from a fictional payments service. Connect a real project to
              see live metrics.
            </p>
            <Button
              asChild
              className="ml-auto shrink-0"
              size="sm"
              variant="outline"
            >
              <Link to="/projects">Add project</Link>
            </Button>
          </div>
        ) : null}

        {/* ── ERROR BANNERS ── */}
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

        {showEmptyState ? (
          <VpwSurface
            aria-label="No project selected — getting started"
            className="border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] px-8 py-10"
          >
            <div className="mx-auto max-w-lg">
              <div className="flex flex-col items-center text-center">
                <div className="mb-4 flex size-14 items-center justify-center rounded-[var(--vpw-radius-lg)] bg-[var(--vpw-navy)] shadow-[var(--vpw-shadow-2)]">
                  <ShieldCheck className="size-7 text-[var(--vpw-amber)]" />
                </div>
                <h3 className="text-lg font-semibold text-slate-900">
                  Set up Risk Operations
                </h3>
                <p className="mt-2 max-w-sm text-sm text-muted-foreground">
                  Select a project, import findings, and run analysis to
                  activate the full Risk Operations cockpit.
                </p>
                <div className="mt-5 flex flex-wrap justify-center gap-2">
                  <Button asChild size="sm">
                    <Link to="/imports">
                      <Import aria-hidden="true" className="size-4" />
                      Import findings
                    </Link>
                  </Button>
                  <Button asChild size="sm" variant="outline">
                    <Link to="/projects">View projects</Link>
                  </Button>
                </div>
              </div>
              <hr className="my-6 border-slate-200" />
              <div className="grid grid-cols-3 gap-4 text-center">
                <div>
                  <div className="mx-auto mb-2 flex size-7 items-center justify-center rounded-[var(--vpw-radius-pill)] bg-[var(--vpw-bg-panel)] text-xs font-bold text-[var(--vpw-text-muted)]">
                    1
                  </div>
                  <p className="text-xs font-medium text-slate-700">
                    Select or create a project
                  </p>
                </div>
                <div>
                  <div className="mx-auto mb-2 flex size-7 items-center justify-center rounded-[var(--vpw-radius-pill)] bg-[var(--vpw-bg-panel)] text-xs font-bold text-[var(--vpw-text-muted)]">
                    2
                  </div>
                  <p className="text-xs font-medium text-slate-700">
                    Import scanner findings
                  </p>
                </div>
                <div>
                  <div className="mx-auto mb-2 flex size-7 items-center justify-center rounded-[var(--vpw-radius-pill)] bg-[var(--vpw-bg-panel)] text-xs font-bold text-[var(--vpw-text-muted)]">
                    3
                  </div>
                  <p className="text-xs font-medium text-slate-700">
                    Run analysis to prioritize
                  </p>
                </div>
              </div>
            </div>
          </VpwSurface>
        ) : null}

        {/* ── TWO-COLUMN GRID: main content + side panel ── */}
        <div className="grid gap-4 lg:grid-cols-[1fr_196px]">
          {/* ── MAIN COLUMN ── */}
          <div className="min-w-0 space-y-4">
            {/* KPI GRID */}
            {isLoading ? (
              <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                {Array.from({ length: 6 }, (_, i) => i).map((i) => (
                  <Skeleton className="h-24 rounded-xl" key={i} />
                ))}
              </div>
            ) : (
              <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                {freshnessCard.map((card) => (
                  <MetricCard
                    detail={card.detail}
                    icon={card.icon}
                    key={card.label}
                    label={card.label}
                    tone={card.tone}
                    value={card.value}
                  />
                ))}
              </div>
            )}

            {/* VISUAL SUMMARIES */}
            <VpwSurface className="gap-2 py-4">
              <VpwSurfaceHeader>
                <VpwSurfaceTitle>Signal Overview</VpwSurfaceTitle>
                <VpwSurfaceDescription>
                  Signal concentration, service risk, and trend direction for
                  executive review.
                </VpwSurfaceDescription>
              </VpwSurfaceHeader>
              <VpwSurfaceBody>
                <Tabs className="w-full" defaultValue="priority">
                  <TabsList className="mb-3 h-8 text-xs">
                    <TabsTrigger value="priority">
                      Findings by Priority
                    </TabsTrigger>
                    <TabsTrigger value="epss">EPSS Distribution</TabsTrigger>
                    <TabsTrigger value="services">Top Services</TabsTrigger>
                    <TabsTrigger value="trend">Risk Trend</TabsTrigger>
                  </TabsList>

                  <TabsContent className="mt-4" value="priority">
                    <ChartCard
                      description="Severity distribution across open findings"
                      title="Findings by priority"
                    >
                      {summaryLoading ? (
                        <Skeleton className="h-64" />
                      ) : priorityItems.length === 0 ? (
                        <EmptyState
                          action={
                            <Button asChild size="sm" variant="outline">
                              <Link to="/imports">Import findings</Link>
                            </Button>
                          }
                          ariaLabel="No priority data"
                          compact
                          detail="Import findings to populate priority distribution."
                          title="No findings yet"
                        />
                      ) : (
                        <ResponsiveContainer height={196} width="100%">
                          <BarChart
                            data={priorityItems}
                            margin={{ bottom: 0, left: 0, right: 6, top: 6 }}
                          >
                            <CartesianGrid
                              className="opacity-40"
                              strokeDasharray="3 3"
                            />
                            <XAxis dataKey="label" tick={{ fontSize: 12 }} />
                            <YAxis tick={{ fontSize: 12 }} />
                            <RechartsTooltip />
                            <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                              {priorityItems.map((entry) => (
                                <Cell
                                  key={entry.label}
                                  fill={
                                    entry.tone === "critical"
                                      ? "#ef4444"
                                      : entry.tone === "high"
                                        ? "#f97316"
                                        : entry.tone === "medium"
                                          ? "#f59e0b"
                                          : entry.tone === "low"
                                            ? "#22c55e"
                                            : "#64748b"
                                  }
                                />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      )}
                    </ChartCard>
                  </TabsContent>

                  <TabsContent className="mt-4" value="epss">
                    <ChartCard
                      description="EPSS bucket distribution for exploit likelihood"
                      title="EPSS exploit probability"
                    >
                      {summaryLoading ? (
                        <Skeleton className="h-64" />
                      ) : epssItems.length === 0 ||
                        epssItems.every((e) => e.value === 0) ? (
                        <EmptyState
                          action={
                            <Button asChild size="sm" variant="outline">
                              <Link to="/imports">Run import</Link>
                            </Button>
                          }
                          ariaLabel="No EPSS data"
                          compact
                          detail="EPSS signals need a provider-enriched import to display buckets."
                          title="No EPSS data"
                        />
                      ) : (
                        <ResponsiveContainer height={196} width="100%">
                          <BarChart
                            data={epssItems}
                            margin={{ bottom: 0, left: 0, right: 6, top: 6 }}
                          >
                            <CartesianGrid
                              className="opacity-40"
                              strokeDasharray="3 3"
                            />
                            <XAxis dataKey="label" tick={{ fontSize: 12 }} />
                            <YAxis tick={{ fontSize: 12 }} />
                            <RechartsTooltip />
                            <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                              {epssItems.map((entry) => (
                                <Cell
                                  key={entry.label}
                                  fill={
                                    entry.tone === "critical"
                                      ? "#ef4444"
                                      : entry.tone === "high"
                                        ? "#f97316"
                                        : entry.tone === "medium"
                                          ? "#f59e0b"
                                          : "#22c55e"
                                  }
                                />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      )}
                    </ChartCard>
                  </TabsContent>

                  <TabsContent className="mt-4" value="services">
                    <ChartCard
                      description={
                        topServiceSource === "assets"
                          ? "Assets with highest accumulated risk score"
                          : "Services with highest accumulated risk score"
                      }
                      title={
                        topServiceSource === "assets"
                          ? "Top Assets by Risk"
                          : "Top Services by Risk"
                      }
                    >
                      {governanceLoading ? (
                        <Skeleton className="h-72" />
                      ) : serviceItems.length === 0 ? (
                        <EmptyState
                          action={
                            <Button asChild size="sm" variant="outline">
                              <Link to="/findings">Review findings</Link>
                            </Button>
                          }
                          ariaLabel="No service risk data"
                          compact
                          detail="Add ownership or component labels and rerun analysis to build entity rankings."
                          title="No rollup data"
                        />
                      ) : (
                        <ResponsiveContainer height={220} width="100%">
                          <BarChart
                            data={serviceItems}
                            margin={{ bottom: 0, left: 0, right: 6, top: 6 }}
                          >
                            <CartesianGrid
                              className="opacity-40"
                              strokeDasharray="3 3"
                            />
                            <XAxis dataKey="label" tick={{ fontSize: 12 }} />
                            <YAxis tick={{ fontSize: 12 }} />
                            <RechartsTooltip />
                            <Bar
                              dataKey="value"
                              fill="#0d9488"
                              radius={[4, 4, 0, 0]}
                            />
                          </BarChart>
                        </ResponsiveContainer>
                      )}
                    </ChartCard>
                  </TabsContent>

                  <TabsContent className="mt-4" value="trend">
                    <ChartCard
                      action={
                        <Select
                          onValueChange={(value: DashboardRunRange) =>
                            setFilters((current) => ({
                              ...current,
                              selectedRunRange: value,
                            }))
                          }
                          value={filters.selectedRunRange}
                        >
                          <SelectTrigger className="w-36">
                            <SelectValue placeholder="Range" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="10">Last 10 runs</SelectItem>
                            <SelectItem value="30">Last 30 runs</SelectItem>
                            <SelectItem value="all">All runs</SelectItem>
                          </SelectContent>
                        </Select>
                      }
                      description="Imported run cadence and trend signal over time"
                      title="Risk trend"
                    >
                      {runsLoading ? (
                        <Skeleton className="h-72" />
                      ) : trendItems.length === 0 ? (
                        <EmptyState
                          action={
                            <Button asChild size="sm" variant="outline">
                              <Link to="/imports">Create first import</Link>
                            </Button>
                          }
                          ariaLabel="No trend data"
                          compact
                          detail="Run at least one import to generate trend history."
                          title="No trend data"
                        />
                      ) : (
                        <ResponsiveContainer height={220} width="100%">
                          <LineChart
                            data={trendItems}
                            margin={{ bottom: 0, left: 0, right: 6, top: 6 }}
                          >
                            <CartesianGrid
                              className="opacity-40"
                              strokeDasharray="3 3"
                            />
                            <XAxis dataKey="label" tick={{ fontSize: 12 }} />
                            <YAxis tick={{ fontSize: 12 }} />
                            <RechartsTooltip />
                            <Line
                              dataKey="value"
                              dot={{ r: 3 }}
                              stroke="#6366f1"
                              strokeWidth={2}
                              type="monotone"
                            />
                          </LineChart>
                        </ResponsiveContainer>
                      )}
                    </ChartCard>
                  </TabsContent>
                </Tabs>
              </VpwSurfaceBody>
            </VpwSurface>

            {/* TOP REMEDIATION QUEUE */}
            <VpwSurface className="gap-2 py-4">
              <VpwSurfaceHeader className="px-4">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <VpwSurfaceTitle>Top Remediation Queue</VpwSurfaceTitle>
                    <VpwSurfaceDescription>
                      Prioritized items ranked by risk score for immediate
                      action.
                    </VpwSurfaceDescription>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <Input
                      aria-label="Filter remediation queue"
                      className="w-40"
                      onChange={(event) =>
                        setFilters((current) => ({
                          ...current,
                          queueSearch: event.currentTarget.value,
                        }))
                      }
                      placeholder="Filter CVE, owner, component…"
                      value={filters.queueSearch}
                    />
                    <Button
                      aria-label="Search"
                      size="icon"
                      type="button"
                      variant="secondary"
                    >
                      <Search className="size-4" />
                    </Button>
                  </div>
                </div>
              </VpwSurfaceHeader>
              <VpwSurfaceBody className="px-0 pb-2">
                {findingsLoading ? (
                  <div className="px-6">
                    <Skeleton className="h-64" />
                  </div>
                ) : findingsError ? (
                  <div className="px-6">
                    <ErrorState message={findingsError} />
                  </div>
                ) : queueFindings.length === 0 ? (
                  <div className="px-6">
                    <EmptyState
                      ariaLabel="No remediation queue items"
                      compact
                      detail={
                        filters.queueSearch
                          ? "No rows match the current filter."
                          : "No items are currently available for remediation from this project."
                      }
                      title={
                        filters.queueSearch
                          ? "No matching findings"
                          : "No findings"
                      }
                    />
                  </div>
                ) : (
                  <Table className="table-fixed">
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-20">Priority</TableHead>
                        <TableHead className="w-20">
                          <Tooltip>
                            <TooltipTrigger className="cursor-default underline decoration-dotted underline-offset-2">
                              Risk Score
                            </TooltipTrigger>
                            <TooltipContent
                              side="top"
                              className="max-w-56 text-xs"
                            >
                              Composite score (0–10) combining CVSS severity,
                              EPSS exploitation probability, KEV status, and
                              asset exposure.
                            </TooltipContent>
                          </Tooltip>
                        </TableHead>
                        <TableHead className="w-36">CVE</TableHead>
                        <TableHead className="w-36">
                          Component / Service
                        </TableHead>
                        <TableHead className="w-24">Owner</TableHead>
                        <TableHead className="w-24">Why now</TableHead>
                        <TableHead className="w-12"></TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {queueFindings.map((finding) => (
                        <TableRow key={finding.id}>
                          <TableCell>
                            <SeverityBadge severity={finding.priority} />
                          </TableCell>
                          <TableCell>
                            <RiskBadge score={finding.risk_score} />
                          </TableCell>
                          <TableCell>
                            <Button
                              asChild
                              className="h-auto px-0 font-mono text-sm"
                              variant="link"
                            >
                              <Link
                                params={{ findingId: finding.id }}
                                to="/findings/$findingId"
                              >
                                {finding.cve_id}
                              </Link>
                            </Button>
                          </TableCell>
                          <TableCell>
                            <div className="max-w-[140px] min-w-0">
                              <p className="truncate text-sm font-medium">
                                {optionalText(finding.component_name)}
                              </p>
                              <p className="truncate text-xs text-muted-foreground">
                                {optionalText(finding.business_service)}
                              </p>
                            </div>
                          </TableCell>
                          <TableCell className="text-sm">
                            {optionalText(finding.owner)}
                          </TableCell>
                          <TableCell>
                            <Dialog>
                              <DialogTrigger asChild>
                                <Button
                                  className="text-xs"
                                  size="sm"
                                  variant="ghost"
                                >
                                  Why now
                                </Button>
                              </DialogTrigger>
                              <DialogContent>
                                <DialogHeader>
                                  <DialogTitle>
                                    Why now: {finding.cve_id}
                                  </DialogTitle>
                                  <DialogDescription>
                                    Current priority rationale from scoring and
                                    operational context.
                                  </DialogDescription>
                                </DialogHeader>
                                <p className="text-sm text-muted-foreground">
                                  {findingWhyNow(finding)}
                                </p>
                                <DialogClose asChild>
                                  <Button
                                    size="sm"
                                    type="button"
                                    variant="secondary"
                                  >
                                    Close
                                  </Button>
                                </DialogClose>
                              </DialogContent>
                            </Dialog>
                          </TableCell>
                          <TableCell>
                            <Sheet>
                              <SheetTrigger asChild>
                                <Button
                                  aria-label="View finding"
                                  size="icon"
                                  variant="default"
                                  className="size-8"
                                >
                                  <Eye
                                    aria-hidden="true"
                                    className="size-3.5"
                                  />
                                </Button>
                              </SheetTrigger>
                              <SheetContent className="overflow-y-auto w-[380px] sm:w-[460px]">
                                <SheetHeader>
                                  <SheetTitle className="font-mono">
                                    {finding.cve_id ?? "Finding"}
                                  </SheetTitle>
                                  <SheetDescription>
                                    Quick view — open full detail for complete
                                    context.
                                  </SheetDescription>
                                </SheetHeader>
                                <div className="mt-6 space-y-5">
                                  <div className="flex flex-wrap gap-2">
                                    <SeverityBadge
                                      severity={finding.priority}
                                    />
                                    <RiskBadge score={finding.risk_score} />
                                  </div>
                                  <dl className="space-y-3 text-sm">
                                    <div>
                                      <dt className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                                        Component
                                      </dt>
                                      <dd className="mt-0.5">
                                        {finding.component_name ?? "—"}
                                      </dd>
                                    </div>
                                    <div>
                                      <dt className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                                        Service
                                      </dt>
                                      <dd className="mt-0.5">
                                        {finding.business_service ?? "—"}
                                      </dd>
                                    </div>
                                    <div>
                                      <dt className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                                        Owner
                                      </dt>
                                      <dd className="mt-0.5">
                                        {finding.owner ?? "—"}
                                      </dd>
                                    </div>
                                    <div>
                                      <dt className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                                        Why now
                                      </dt>
                                      <dd className="mt-0.5 text-muted-foreground">
                                        {findingWhyNow(finding)}
                                      </dd>
                                    </div>
                                  </dl>
                                  <Button
                                    asChild
                                    className="w-full"
                                    size="sm"
                                    variant="outline"
                                  >
                                    <Link
                                      params={{ findingId: finding.id }}
                                      to="/findings/$findingId"
                                    >
                                      Open full detail
                                    </Link>
                                  </Button>
                                </div>
                              </SheetContent>
                            </Sheet>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </VpwSurfaceBody>
            </VpwSurface>
          </div>

          {/* ── SIDE PANEL ── */}
          <div className="space-y-3">
            {/* Provider Freshness */}
            <VpwSurface className="gap-3 py-4">
              <VpwSurfaceHeader className="pb-0 px-4">
                <VpwSurfaceTitle className="text-xs font-bold uppercase tracking-wide text-muted-foreground">
                  Provider Freshness
                </VpwSurfaceTitle>
              </VpwSurfaceHeader>
              <VpwSurfaceBody className="space-y-2 px-4">
                <div className="flex items-center gap-2">
                  <ProviderStatusBadge
                    status={
                      effectiveProviderStatus?.status ??
                      (providerStatusLoading ? "loading" : "unknown")
                    }
                  />
                  <span className="text-sm font-bold">{freshness.value}</span>
                </div>
                <p className="text-xs leading-relaxed text-muted-foreground">
                  {freshness.detail}
                </p>
                {providerStatusLoading && <Skeleton className="h-4 w-32" />}
              </VpwSurfaceBody>
            </VpwSurface>

            {/* Evidence Readiness */}
            <VpwSurface className="gap-3 py-4">
              <VpwSurfaceHeader className="pb-0 px-4">
                <VpwSurfaceTitle className="text-xs font-bold uppercase tracking-wide text-muted-foreground">
                  Evidence Readiness
                </VpwSurfaceTitle>
              </VpwSurfaceHeader>
              <VpwSurfaceBody className="px-4">
                <dl className="space-y-2 text-sm">
                  <div className="flex items-center justify-between">
                    <dt className="text-muted-foreground">Latest run</dt>
                    <dd className="max-w-32.5 truncate text-right text-xs font-medium">
                      {latestRunLabel(latestRun)}
                    </dd>
                  </div>
                  <div className="flex items-center justify-between">
                    <dt className="text-muted-foreground">Findings</dt>
                    <dd className="font-semibold">
                      {effectiveSummary?.finding_count ?? 0}
                    </dd>
                  </div>
                  <div className="flex items-center justify-between">
                    <dt className="text-muted-foreground">Runs</dt>
                    <dd className="font-semibold">{effectiveRuns.length}</dd>
                  </div>
                  <div className="flex items-center justify-between border-t pt-2">
                    <dt className="text-muted-foreground">Evidence quality</dt>
                    <dd>
                      <Badge
                        className="text-xs"
                        variant={staleProvider ? "destructive" : "secondary"}
                      >
                        {staleProvider ? "Needs sync" : "Healthy"}
                      </Badge>
                    </dd>
                  </div>
                </dl>
              </VpwSurfaceBody>
            </VpwSurface>

            {/* Data Quality Notes */}
            <VpwSurface className="gap-3 py-4">
              <VpwSurfaceHeader className="pb-0 px-4">
                <VpwSurfaceTitle className="text-xs font-bold uppercase tracking-wide text-muted-foreground">
                  Data Quality
                </VpwSurfaceTitle>
              </VpwSurfaceHeader>
              <VpwSurfaceBody className="px-4">
                {dataQualityWarnings.length === 0 && !dataQualityError ? (
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <CheckCircle2 className="size-3.5 shrink-0 text-green-500" />
                    <span>No data quality issues detected.</span>
                  </div>
                ) : (
                  <ul className="space-y-2">
                    {dataQualityWarnings.map((warning) => (
                      <li className="flex gap-2 text-xs" key={warning}>
                        <AlertCircle
                          aria-hidden="true"
                          className="mt-0.5 size-3.5 shrink-0 text-amber-500"
                        />
                        <span className="leading-relaxed text-muted-foreground">
                          {warning}
                        </span>
                      </li>
                    ))}
                    {dataQualityError && (
                      <li className="flex gap-2 text-xs">
                        <AlertCircle
                          aria-hidden="true"
                          className="mt-0.5 size-3.5 shrink-0 text-red-500"
                        />
                        <span className="leading-relaxed text-muted-foreground">
                          {dataQualityError}
                        </span>
                      </li>
                    )}
                  </ul>
                )}
              </VpwSurfaceBody>
            </VpwSurface>

            {/* Recent Runs */}
            <VpwSurface className="gap-3 py-4">
              <VpwSurfaceHeader className="pb-0 px-4">
                <VpwSurfaceTitle className="text-xs font-bold uppercase tracking-wide text-muted-foreground">
                  Recent Runs
                </VpwSurfaceTitle>
              </VpwSurfaceHeader>
              <VpwSurfaceBody className="px-4">
                {latestRunFactsRows.length === 0 ? (
                  <p className="text-xs text-muted-foreground">
                    No analysis runs yet.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {latestRunFactsRows.map((run) => (
                      <div
                        className="flex items-center justify-between gap-2 rounded-md border bg-muted/20 px-2.5 py-2 text-xs"
                        key={run.id}
                      >
                        <Badge
                          className="shrink-0"
                          variant={
                            run.tone === "succeeded"
                              ? "secondary"
                              : "destructive"
                          }
                        >
                          {run.status}
                        </Badge>
                        <span className="truncate text-muted-foreground">
                          {run.startedAt}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
                <Button
                  asChild
                  className="mt-3 w-full"
                  size="sm"
                  variant="outline"
                >
                  <Link to="/imports">View all imports</Link>
                </Button>
              </VpwSurfaceBody>
            </VpwSurface>
          </div>
        </div>
      </section>
    </TooltipProvider>
  )
}
