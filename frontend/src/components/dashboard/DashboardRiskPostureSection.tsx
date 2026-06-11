import { Link, useLocation, useNavigate } from "@/lib/router"
import { lazy, Suspense, useCallback, useMemo } from "react"
import type {
  ProjectRiskInsightsPublic,
  RiskTrendPointPublic,
} from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Callout,
  EmptyState,
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import {
  RISK_TARGET_SCORE,
  riskAverageTrendData,
  riskScoreBand,
} from "@/lib/chart-data"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import type { DashboardRunRange } from "./dashboard-model"
import { DashboardMitigationLeverList } from "./DashboardMitigationLeverList"
import { DashboardRiskRoadmap } from "./DashboardRiskRoadmap"
import { DashboardRiskScenarioPanel } from "./DashboardRiskScenarioPanel"
import { DashboardTopDriverStrip } from "./DashboardTopDriverStrip"
import {
  buildRiskScenario,
  riskLeverSearchWithSelection,
  selectedRiskLeverIdsFromSearch,
} from "./dashboard-risk-scenario-model"

const DashboardRiskAverageChart = lazy(
  () => import("./DashboardRiskAverageChart"),
)

const BAND_LABELS: Record<string, string> = {
  critical: "Critical band",
  high: "High band",
  low: "Low band",
  medium: "Medium band",
}

type DashboardRiskPostureSectionProps = {
  onRunRangeChange: (value: DashboardRunRange) => void
  riskInsights: ProjectRiskInsightsPublic | null
  riskInsightsError: string
  riskInsightsLoading: boolean
  selectedProjectId: string
  selectedRunRange: DashboardRunRange
}

export function DashboardRiskPostureSection({
  onRunRangeChange,
  riskInsights,
  riskInsightsError,
  riskInsightsLoading,
  selectedProjectId,
  selectedRunRange,
}: DashboardRiskPostureSectionProps) {
  const location = useLocation()
  const navigate = useNavigate()
  const projectSearch = selectedProjectRouteSearch(selectedProjectId)
  const trendPoints = riskInsights?.trend ?? []
  const trendItems = useMemo(
    () =>
      riskAverageTrendData(trendPoints, Number.parseInt(selectedRunRange, 10)),
    [trendPoints, selectedRunRange],
  )
  const levers = riskInsights?.mitigation_levers ?? []
  const baselineAverage = riskInsights?.baseline_average_risk_score ?? null
  const openCount = riskInsights?.baseline_open_finding_count ?? 0
  const totalOpenRiskScore =
    riskInsights?.baseline_total_risk_score ??
    (baselineAverage !== null ? Math.round(baselineAverage * openCount) : null)
  const riskTargetScore = riskInsights?.risk_target_score ?? RISK_TARGET_SCORE
  const recommendedLeverId = riskInsights?.recommended_lever_id ?? null
  const selectedLeverIds = useMemo(
    () =>
      selectedRiskLeverIdsFromSearch(
        location.searchStr,
        levers,
        recommendedLeverId,
      ),
    [levers, location.searchStr, recommendedLeverId],
  )
  const defaultLeverIds = useMemo(
    () => selectedRiskLeverIdsFromSearch("", levers, recommendedLeverId),
    [levers, recommendedLeverId],
  )
  const scenario = useMemo(
    () =>
      buildRiskScenario({
        baselineAverageRiskScore: baselineAverage,
        baselineOpenFindingCount: openCount,
        baselineTotalRiskScore: totalOpenRiskScore,
        levers,
        riskTargetScore,
        selectedLeverIds,
      }),
    [
      baselineAverage,
      levers,
      openCount,
      riskTargetScore,
      selectedLeverIds,
      totalOpenRiskScore,
    ],
  )
  const updateLeverSelection = useCallback(
    (nextLeverIds: string[]) => {
      void navigate({
        replace: true,
        search: riskLeverSearchWithSelection(
          location.searchStr,
          nextLeverIds,
        ),
      })
    },
    [location.searchStr, navigate],
  )
  const resetLeverSelection = useCallback(() => {
    updateLeverSelection(defaultLeverIds)
  }, [defaultLeverIds, updateLeverSelection])
  const latestKevCount = latestScoredPoint(trendPoints)?.kev_count ?? null
  const averageShift = trendAverageShift(trendPoints)
  const bandTone = baselineAverage !== null ? riskScoreBand(baselineAverage) : null
  const hasInsights = trendItems.length > 0 || levers.length > 0

  return (
    <VpwSurface className="gap-2 py-4">
      <VpwSurfaceHeader>
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <VpwSurfaceTitle>Risk Posture</VpwSurfaceTitle>
            <VpwSurfaceDescription>
              Average operational risk per analysis run and the actions with
              the biggest risk reduction.
            </VpwSurfaceDescription>
          </div>
          <Select onValueChange={onRunRangeChange} value={selectedRunRange}>
            <SelectTrigger
              aria-label="Risk posture run range"
              className="w-36 shrink-0"
            >
              <SelectValue placeholder="Range" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="10">Last 10 runs</SelectItem>
              <SelectItem value="30">Last 30 runs</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </VpwSurfaceHeader>
      <VpwSurfaceBody className="flex flex-col gap-4 pb-4">
        {riskInsightsLoading ? (
          <Skeleton className="h-72" />
        ) : riskInsightsError ? (
          <Callout severity="critical" title="Risk insights unavailable">
            {riskInsightsError}
          </Callout>
        ) : !hasInsights ? (
          <EmptyState
            action={
              <Button asChild size="sm" variant="outline">
                <Link search={projectSearch} to="/imports">
                  Import scan results
                </Link>
              </Button>
            }
            ariaLabel="No risk posture data"
            className="min-h-0 py-4"
            description="Import scan results to build the risk trend and mitigation levers."
            title="No risk data yet"
          />
        ) : (
          <>
            <div
              className="risk-kpi-row risk-tone"
              data-tone={bandTone ?? "standard"}
            >
              <div className="risk-kpi">
                <span className="risk-micro-label">Current avg risk</span>
                <span className="risk-kpi-value">
                  {baselineAverage ?? "—"}
                  <span className="risk-kpi-unit">/ 100</span>
                  {bandTone ? (
                    <span className="risk-band-chip">
                      {BAND_LABELS[bandTone]}
                    </span>
                  ) : null}
                  {averageShift !== null ? (
                    <span
                      className="risk-delta-pill"
                      data-direction={averageShift <= 0 ? "down" : "up"}
                    >
                      {averageShift <= 0 ? "▼" : "▲"} {Math.abs(averageShift)}
                      <span className="font-normal">vs previous run</span>
                    </span>
                  ) : null}
                </span>
              </div>
              <div aria-hidden="true" className="risk-kpi-divider" />
              <div className="risk-kpi">
                <span className="risk-micro-label">Open findings</span>
                <span className="risk-kpi-value risk-kpi-value--plain">
                  {openCount}
                </span>
              </div>
              {latestKevCount !== null ? (
                <>
                  <div aria-hidden="true" className="risk-kpi-divider" />
                  <div className="risk-kpi">
                    <span className="risk-micro-label">KEV open</span>
                    <span className="risk-kpi-value risk-kpi-value--plain">
                      {latestKevCount}
                    </span>
                  </div>
                </>
              ) : null}
              {trendItems.length < 2 ? (
                <span className="self-center text-xs text-muted-foreground">
                  Import again to compare runs
                </span>
              ) : null}
            </div>
            <DashboardTopDriverStrip
              driver={riskInsights?.top_driver ?? null}
              selectedProjectId={selectedProjectId}
            />
            <div className="risk-visual-grid">
              <div className="grid min-w-0 content-start gap-2">
                <span className="risk-micro-label">
                  Average risk per analysis run
                </span>
                <Suspense fallback={<Skeleton className="h-64" />}>
                  <DashboardRiskAverageChart height={256} items={trendItems} />
                </Suspense>
              </div>
              <DashboardRiskScenarioPanel
                canReset={!sameSelection(selectedLeverIds, defaultLeverIds)}
                onClearSelection={() => updateLeverSelection([])}
                onResetSelection={resetLeverSelection}
                scenario={scenario}
              />
            </div>
            <div className="risk-workbench-grid">
              <div className="grid min-w-0 content-start gap-2">
                <span className="risk-micro-label">
                  Top mitigation levers · what-if selection
                </span>
                <DashboardMitigationLeverList
                  levers={levers}
                  onSelectionChange={updateLeverSelection}
                  recommendedLeverId={recommendedLeverId}
                  selectable
                  selectedLeverIds={selectedLeverIds}
                  totalOpenRiskScore={totalOpenRiskScore}
                />
              </div>
              <DashboardRiskRoadmap
                levers={levers}
                selectedLeverIds={selectedLeverIds}
              />
            </div>
          </>
        )}
      </VpwSurfaceBody>
    </VpwSurface>
  )
}

function sameSelection(first: readonly string[], second: readonly string[]) {
  if (first.length !== second.length) {
    return false
  }
  return first.every((value, index) => value === second[index])
}

function latestScoredPoint(
  points: readonly RiskTrendPointPublic[],
): RiskTrendPointPublic | null {
  for (let index = points.length - 1; index >= 0; index -= 1) {
    if (points[index].average_risk_score !== null) {
      return points[index]
    }
  }
  return points.length > 0 ? points[points.length - 1] : null
}

function trendAverageShift(
  points: readonly RiskTrendPointPublic[],
): number | null {
  const scored = points.filter(
    (point) =>
      point.average_risk_score !== null &&
      point.average_risk_score !== undefined,
  )
  if (scored.length < 2) {
    return null
  }
  const latest = scored[scored.length - 1].average_risk_score ?? 0
  const previous = scored[scored.length - 2].average_risk_score ?? 0
  return Math.round((latest - previous) * 10) / 10
}
