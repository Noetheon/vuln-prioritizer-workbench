import type { CSSProperties } from "react"
import { useEffect, useMemo, useRef, useState } from "react"
import {
  ArrowUpRight,
  CheckSquare2,
  ShieldCheck,
  Square,
  Target,
  TrendingDown,
} from "lucide-react"

import type {
  ProjectDecisionSummaryPublic,
  ProjectRiskReductionPublic,
  RiskReductionOpportunityPublic,
} from "@/api-client"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import {
  EmptyState,
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import { findingsByPriorityChartData } from "@/lib/chart-data"
import { Link } from "@/lib/router"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  buildRiskPostureHistorySteps,
  buildRiskPostureProjection,
  buildRiskReductionSummary,
  formatRiskReductionScore,
  riskReducerMetaLabel,
  riskReductionPercent,
  riskScoreToIndex,
  selectedRiskPostureReducers,
  shortContextList,
  type RiskPostureHistoryStep,
  type RiskPostureProjectionStep,
  type RiskReductionSummary,
} from "./dashboard-risk-reduction-model"

type DashboardRiskReductionPanelProps = {
  isLoading: boolean
  projectSummary: ProjectDecisionSummaryPublic | null
  riskReduction: ProjectRiskReductionPublic | null
  selectedProjectId: string
}

export function DashboardRiskReductionPanel({
  isLoading,
  projectSummary,
  riskReduction,
  selectedProjectId,
}: DashboardRiskReductionPanelProps) {
  const summary = useMemo(
    () => buildRiskReductionSummary(riskReduction),
    [riskReduction],
  )
  const [selectedOpportunityIds, setSelectedOpportunityIds] = useState<
    Set<string>
  >(() => selectedRiskPostureReducers(summary.opportunities))

  useEffect(() => {
    setSelectedOpportunityIds(
      selectedRiskPostureReducers(summary.opportunities),
    )
  }, [summary.opportunities])

  const projection = useMemo(
    () => buildRiskPostureProjection(summary, selectedOpportunityIds),
    [selectedOpportunityIds, summary],
  )
  const historySteps = useMemo(
    () => buildRiskPostureHistorySteps(summary.history),
    [summary.history],
  )
  const checkedPlan = projection[projection.length - 1] ?? projection[0] ?? null
  const checkedReductionIndex = Math.max(
    summary.currentRiskIndex - (checkedPlan?.riskIndex ?? 0),
    0,
  )

  return (
    <VpwSurface
      aria-label="Risk posture"
      className="dashboard-risk-posture"
      role="region"
    >
      <VpwSurfaceHeader className="dashboard-risk-posture-header">
        <div className="dashboard-risk-posture-heading">
          <div>
            <VpwSurfaceTitle className="dashboard-risk-posture-title">
              Risk posture
            </VpwSurfaceTitle>
            <VpwSurfaceDescription>
              Where open risk stands and which remediation groups move it most.
            </VpwSurfaceDescription>
          </div>
        </div>
      </VpwSurfaceHeader>
      <VpwSurfaceBody>
        {isLoading ? (
          <RiskPostureLoading />
        ) : summary.hasOpportunities ? (
          <div className="dashboard-risk-posture-grid">
            <RiskPostureSummary
              checkedReductionIndex={checkedReductionIndex}
              projectSummary={projectSummary}
              summary={summary}
            />
            <RiskPostureProjection
              currentRiskIndex={summary.currentRiskIndex}
              historySteps={historySteps}
              projection={projection}
              selectedCount={selectedOpportunityIds.size}
              targetIndex={summary.simulationTargetIndex}
            />
            <RiskPostureReducers
              selectedOpportunityIds={selectedOpportunityIds}
              selectedProjectId={selectedProjectId}
              setSelectedOpportunityIds={setSelectedOpportunityIds}
              summary={summary}
            />
          </div>
        ) : (
          <EmptyState
            action={
              <Button asChild size="sm" variant="outline">
                <Link
                  search={selectedProjectRouteSearch(selectedProjectId)}
                  to="/findings"
                >
                  Review findings
                  <ArrowUpRight aria-hidden="true" className="size-3.5" />
                </Link>
              </Button>
            }
            ariaLabel="No open reduction opportunities"
            className="min-h-0 py-8"
            icon={<ShieldCheck aria-hidden="true" className="size-5" />}
            title="No open reduction opportunities"
            description="No open, in-review, or remediating findings currently contribute direct actionable risk."
          />
        )}
      </VpwSurfaceBody>
    </VpwSurface>
  )
}

function RiskPostureLoading() {
  return (
    <div className="dashboard-risk-posture-loading">
      <Skeleton className="h-72" />
      <Skeleton className="h-72" />
      <Skeleton className="h-72" />
    </div>
  )
}

function RiskPostureSummary({
  checkedReductionIndex,
  projectSummary,
  summary,
}: {
  checkedReductionIndex: number
  projectSummary: ProjectDecisionSummaryPublic | null
  summary: RiskReductionSummary
}) {
  const band = riskIndexBand(summary.currentRiskIndex)
  const openFindingCount =
    projectSummary?.open_finding_count ?? summary.actionableFindingCount
  const acceptedRiskCount = statusCount(projectSummary, "accepted")
  return (
    <section
      aria-label="Risk index summary"
      className="dashboard-risk-posture-summary"
    >
      <div className="dashboard-risk-posture-summary-kicker">
        Risk index · avg open findings
      </div>
      <div
        className={`dashboard-risk-posture-index dashboard-risk-posture-index--${band}`}
      >
        {formatRiskReductionScore(summary.currentRiskIndex)}
      </div>
      <div className="dashboard-risk-posture-index-change">
        <TrendingDown aria-hidden="true" className="size-4" />
        <span className="dashboard-risk-posture-index-change-value">
          {formatRiskReductionScore(checkedReductionIndex)}
        </span>
        <span className="dashboard-risk-posture-index-change-label">
          index reduction planned
        </span>
      </div>
      <RiskIndexScale value={summary.currentRiskIndex} />
      <RiskPostureSeverityStrip projectSummary={projectSummary} />
      <div className="dashboard-risk-posture-scope-line">
        <span className="dashboard-risk-posture-scope-item">
          {formatRiskReductionScore(openFindingCount)} open findings in scope ·{" "}
          {formatRiskReductionScore(acceptedRiskCount)} risk-accepted
        </span>
        <span className="dashboard-risk-posture-scope-item">
          {formatRiskReductionScore(summary.governanceDebtRisk)} governance debt
        </span>
      </div>
    </section>
  )
}

function RiskIndexScale({ value }: { value: number }) {
  return (
    <div className="dashboard-risk-posture-scale">
      <div className="dashboard-risk-posture-scale-track">
        <span className="dashboard-risk-posture-scale-band dashboard-risk-posture-scale-band--low" />
        <span className="dashboard-risk-posture-scale-band dashboard-risk-posture-scale-band--moderate" />
        <span className="dashboard-risk-posture-scale-band dashboard-risk-posture-scale-band--critical" />
        <span
          className="dashboard-risk-posture-scale-needle"
          style={riskPostureStyle("--risk-posture-level", `${clamp(value)}%`)}
        />
      </div>
      <div className="dashboard-risk-posture-scale-labels">
        <span>0</span>
        <span>moderate</span>
        <span>100</span>
      </div>
    </div>
  )
}

function RiskPostureSeverityStrip({
  projectSummary,
}: {
  projectSummary: ProjectDecisionSummaryPublic | null
}) {
  const buckets = findingsByPriorityChartData(projectSummary)
  const total = buckets.reduce((sum, bucket) => sum + bucket.value, 0)
  const filledShare = total > 0 ? 100 : 25

  return (
    <div
      aria-label="Open findings by priority"
      className="dashboard-risk-posture-severity"
      role="img"
    >
      <div className="dashboard-risk-posture-severity-track">
        {buckets.map((bucket) => (
          <span
            className={`dashboard-risk-posture-severity-segment dashboard-risk-posture-severity-segment--${bucket.tone}`}
            data-empty={bucket.value <= 0 ? "true" : undefined}
            key={bucket.label}
            style={riskPostureStyle(
              "--risk-posture-severity-width",
              total > 0 && bucket.value > 0
                ? `${(bucket.value / total) * filledShare}%`
                : "0.8rem",
            )}
            title={`${bucket.label}: ${bucket.value}`}
          />
        ))}
      </div>
    </div>
  )
}

type RiskPostureChartBar = {
  detail: string
  key: string
  label: string
  riskIndex: number
  riskScore: number | null
  tone: "critical" | "history" | "low" | "moderate" | "projected" | "success"
}

function RiskPostureProjection({
  currentRiskIndex,
  historySteps,
  projection,
  selectedCount,
  targetIndex,
}: {
  currentRiskIndex: number
  historySteps: readonly RiskPostureHistoryStep[]
  projection: readonly RiskPostureProjectionStep[]
  selectedCount: number
  targetIndex: number
}) {
  const [activeStepKey, setActiveStepKey] = useState<string | null>(null)
  const chartHost = useRef<SVGSVGElement | null>(null)
  const [viewBoxWidth, setViewBoxWidth] = useState(920)
  useEffect(() => {
    const node = chartHost.current
    if (!node || typeof ResizeObserver === "undefined") {
      return
    }
    const observer = new ResizeObserver((entries) => {
      const width = entries[0]?.contentRect.width ?? 0
      if (width > 0) {
        // viewBox tracks the rendered box (height 300px) so the SVG always
        // fills the column instead of letterboxing at wide layouts.
        setViewBoxWidth(
          Math.round(Math.min(1680, Math.max(640, width * (330 / 300)))),
        )
      }
    })
    observer.observe(node)
    return () => observer.disconnect()
  }, [])
  const chartTop = 46
  const chartBottom = 262
  const plotHeight = chartBottom - chartTop
  const chartScale = plotHeight / 100
  const chartLeft = 56
  const chartRight = viewBoxWidth - 16
  const todayGap = 38
  const tickValues = [100, 75, 50, 25, 0]
  const allBars: RiskPostureChartBar[] = [
    ...historySteps.map((step) => ({
      detail: "",
      key: step.key,
      label: step.label,
      riskIndex: step.riskIndex,
      riskScore: null,
      tone: "history" as const,
    })),
    ...projection.map((step) => ({
      detail:
        step.reductionScore > 0
          ? `-${formatRiskReductionScore(step.reductionScore)} score`
          : "open risk",
      key: step.key,
      label: projectionStepDisplayLabel(step.label),
      riskIndex: step.riskIndex,
      riskScore: step.riskScore as number | null,
      tone: chartBarTone(step, targetIndex),
    })),
  ]
  // The dashed divider separates persisted runs from the live state; with
  // no history it still separates "Current" from the simulated plan.
  const dividerIndex = historySteps.length > 0 ? historySteps.length : 1
  const slotWidth =
    allBars.length > 0 ? (chartRight - chartLeft - todayGap) / allBars.length : 0
  const barWidth = Math.round(Math.min(108, Math.max(34, slotWidth * 0.56)))
  const barCenterAt = (index: number) =>
    chartLeft +
    slotWidth * index +
    slotWidth / 2 +
    (index >= dividerIndex ? todayGap : 0)
  const chartBars = allBars.map((bar, index) => ({
    ...bar,
    center: barCenterAt(index),
    height: clamp(bar.riskIndex) * chartScale,
    x: barCenterAt(index) - barWidth / 2,
  }))
  const activeStep =
    chartBars.find((bar) => bar.key === activeStepKey) ??
    chartBars[chartBars.length - 1] ??
    null
  const targetY = chartBottom - clamp(targetIndex) * chartScale
  const todayX = chartLeft + slotWidth * dividerIndex + todayGap / 2
  const historyCaptionX =
    historySteps.length > 1
      ? (barCenterAt(0) + barCenterAt(historySteps.length - 1)) / 2
      : null
  return (
    <section
      aria-label="Scenario projection"
      className="dashboard-risk-posture-projection"
    >
      <div className="dashboard-risk-posture-section-head">
        <div className="dashboard-risk-posture-section-title">
          <Target aria-hidden="true" className="size-4" />
          <span>Scenario projection</span>
        </div>
        <div className="dashboard-risk-posture-legend">
          <span className="dashboard-risk-posture-legend-item dashboard-risk-posture-legend-item--actual">
            actual
          </span>
          <span className="dashboard-risk-posture-legend-item dashboard-risk-posture-legend-item--projected">
            projected (plan)
          </span>
          <span className="dashboard-risk-posture-legend-item dashboard-risk-posture-legend-item--target">
            target
          </span>
        </div>
      </div>
      <div className="dashboard-risk-posture-projection-chart">
        <svg
          aria-label="Scenario risk bar projection"
          className="dashboard-risk-posture-bar-chart"
          preserveAspectRatio="xMidYMin meet"
          ref={chartHost}
          role="img"
          viewBox={`0 0 ${viewBoxWidth} 330`}
        >
          <defs>
            {(
              [
                "critical",
                "moderate",
                "low",
                "projected",
                "success",
                "history",
              ] as const
            ).map(
              (tone) => (
                <linearGradient
                  id={`vpw-risk-posture-grad-${tone}`}
                  key={tone}
                  x1="0"
                  x2="0"
                  y1="0"
                  y2="1"
                >
                  <stop
                    className={`dashboard-risk-posture-grad-stop dashboard-risk-posture-grad-stop--${tone}`}
                    offset="0"
                    stopOpacity={
                      tone === "projected" || tone === "history" ? 0.2 : 0.34
                    }
                  />
                  <stop
                    className={`dashboard-risk-posture-grad-stop dashboard-risk-posture-grad-stop--${tone}`}
                    offset="1"
                    stopOpacity="0.05"
                  />
                </linearGradient>
              ),
            )}
          </defs>
          {tickValues.map((tick) => {
            const y = chartBottom - tick * chartScale
            return (
              <g key={tick}>
                <line
                  className="dashboard-risk-posture-chart-grid-line"
                  x1={chartLeft}
                  x2={chartRight}
                  y1={y}
                  y2={y}
                />
                <text
                  className="dashboard-risk-posture-chart-axis-label"
                  x={chartLeft - 10}
                  y={y + 4}
                >
                  {tick}
                </text>
              </g>
            )
          })}
          {chartBars.length > 1 ? (
            <g>
              <line
                className="dashboard-risk-posture-chart-today"
                x1={todayX}
                x2={todayX}
                y1={chartTop - 12}
                y2={chartBottom}
              />
              <text
                className="dashboard-risk-posture-chart-today-label"
                x={todayX}
                y={chartTop - 20}
              >
                TODAY
              </text>
            </g>
          ) : null}
          <line
            className="dashboard-risk-posture-chart-target"
            x1={chartLeft}
            x2={chartRight}
            y1={targetY}
            y2={targetY}
          />
          <text
            className="dashboard-risk-posture-chart-target-label"
            x={chartRight - 2}
            y={targetY - 8}
          >
            TARGET {formatRiskReductionScore(targetIndex)}
          </text>
          {chartBars.map((bar) => {
            const isActive = activeStep?.key === bar.key
            const barTop = chartBottom - bar.height
            return (
              <g
                aria-label={`${bar.label}: risk index ${formatRiskReductionScore(
                  bar.riskIndex,
                )}${
                  bar.riskScore !== null
                    ? `, open score ${formatRiskReductionScore(bar.riskScore)}`
                    : ""
                }`}
                className="dashboard-risk-posture-bar"
                data-active={isActive ? "true" : undefined}
                key={bar.key}
                onPointerEnter={() => setActiveStepKey(bar.key)}
                onPointerLeave={() => setActiveStepKey(null)}
              >
                <rect
                  className="dashboard-risk-posture-bar-hit"
                  height={plotHeight}
                  width={barWidth + 28}
                  x={bar.x - 14}
                  y={chartTop}
                />
                <text
                  className={`dashboard-risk-posture-bar-value${
                    bar.tone === "history"
                      ? " dashboard-risk-posture-bar-value--muted"
                      : ""
                  }`}
                  x={bar.center}
                  y={barTop - 10}
                >
                  {formatRiskReductionScore(bar.riskIndex)}
                </text>
                <rect
                  className={`dashboard-risk-posture-bar-fill dashboard-risk-posture-bar-fill--${bar.tone}${
                    isActive ? " dashboard-risk-posture-bar-fill--active" : ""
                  }`}
                  height={bar.height}
                  rx="3"
                  ry="3"
                  width={barWidth}
                  x={bar.x}
                  y={barTop}
                />
                <rect
                  className={`dashboard-risk-posture-bar-cap dashboard-risk-posture-bar-cap--${bar.tone}`}
                  height="4.5"
                  rx="2.25"
                  width={barWidth}
                  x={bar.x}
                  y={barTop}
                />
                <text
                  className="dashboard-risk-posture-chart-x-label"
                  x={bar.center}
                  y="288"
                >
                  {bar.label}
                </text>
                {bar.detail ? (
                  <text
                    className="dashboard-risk-posture-chart-x-detail"
                    x={bar.center}
                    y="308"
                  >
                    {bar.detail}
                  </text>
                ) : null}
              </g>
            )
          })}
          {historyCaptionX !== null ? (
            <text
              className="dashboard-risk-posture-chart-x-detail"
              x={historyCaptionX}
              y="308"
            >
              analysis runs (actual)
            </text>
          ) : null}
        </svg>
      </div>
      <RiskPosturePlanReadout
        currentRiskIndex={currentRiskIndex}
        projection={projection}
        selectedCount={selectedCount}
        targetIndex={targetIndex}
      />
    </section>
  )
}

function RiskPosturePlanReadout({
  currentRiskIndex,
  projection,
  selectedCount,
  targetIndex,
}: {
  currentRiskIndex: number
  projection: readonly RiskPostureProjectionStep[]
  selectedCount: number
  targetIndex: number
}) {
  const finalStep = projection[projection.length - 1] ?? null
  const finalIndex = finalStep?.riskIndex ?? currentRiskIndex
  const dropPercent =
    currentRiskIndex > 0
      ? Math.round(((currentRiskIndex - finalIndex) / currentRiskIndex) * 100)
      : 0
  const reachedStep = projection.find((step) => step.riskIndex <= targetIndex)
  return (
    <div className="dashboard-risk-posture-readout">
      <span className="dashboard-risk-posture-readout-chip">
        {selectedCount} action{selectedCount === 1 ? "" : "s"} planned
      </span>
      <span className="dashboard-risk-posture-readout-text">
        Completing the checked plan takes the index{" "}
        <strong>
          {formatRiskReductionScore(currentRiskIndex)} →{" "}
          {formatRiskReductionScore(finalIndex)}
        </strong>{" "}
        (−{dropPercent}%)
        {reachedStep ? (
          <>
            {" "}
            — target reached <strong>{planReadoutStepLabel(reachedStep)}</strong>
          </>
        ) : (
          <>
            {" "}
            —{" "}
            <strong className="dashboard-risk-posture-readout-warn">
              target not reached
            </strong>
            ; check more reducers
          </>
        )}
      </span>
    </div>
  )
}

function planReadoutStepLabel(step: RiskPostureProjectionStep) {
  switch (step.key) {
    case "current":
      return "already"
    case "checked-top-1":
      return "after top 1"
    case "checked-top-3":
      return "after top 3"
    default:
      return "with the checked plan"
  }
}

function RiskPostureReducers({
  selectedOpportunityIds,
  selectedProjectId,
  setSelectedOpportunityIds,
  summary,
}: {
  selectedOpportunityIds: ReadonlySet<string>
  selectedProjectId: string
  setSelectedOpportunityIds: (value: Set<string>) => void
  summary: RiskReductionSummary
}) {
  // Render every opportunity that feeds the checked-plan simulation; hiding
  // any of them would leave un-uncheckable selections behind.
  const reducers = summary.opportunities
  return (
    <section
      aria-label="Top risk reducers"
      className="dashboard-risk-posture-reducers"
    >
      <div className="dashboard-risk-posture-reducers-head">
        <div className="dashboard-risk-posture-section-title">
          <TrendingDown aria-hidden="true" className="size-4" />
          <span>Top risk reducers</span>
        </div>
        <p>Expected reduction if completed - toggle to simulate</p>
      </div>
      <ol>
        {reducers.map((opportunity, index) => {
          const isSelected = selectedOpportunityIds.has(opportunity.id)
          const reductionIndex = riskScoreToIndex(
            opportunity.expected_reduction ?? 0,
            summary.actionableFindingCount,
          )
          return (
            <li
              className="dashboard-risk-posture-reducer"
              data-selected={isSelected ? "true" : "false"}
              key={opportunity.id}
            >
              <div className="dashboard-risk-posture-reducer-main">
                <Button
                  aria-label={`${isSelected ? "Remove" : "Add"} ${
                    opportunity.label
                  } from checked plan`}
                  aria-pressed={isSelected}
                  className="dashboard-risk-posture-reducer-toggle"
                  onClick={() =>
                    toggleReducer(
                      opportunity.id,
                      selectedOpportunityIds,
                      setSelectedOpportunityIds,
                    )
                  }
                  size="icon-xs"
                  type="button"
                  variant="ghost"
                >
                  {isSelected ? (
                    <CheckSquare2 aria-hidden="true" className="size-4" />
                  ) : (
                    <Square aria-hidden="true" className="size-4" />
                  )}
                </Button>
                <div className="dashboard-risk-posture-reducer-copy">
                  <Link
                    className="dashboard-risk-posture-reducer-link"
                    search={opportunityRouteSearch(
                      opportunity,
                      selectedProjectId,
                    )}
                    to="/findings"
                  >
                    {reducerTitle(opportunity)}
                  </Link>
                </div>
                <div className="dashboard-risk-posture-reducer-impact">
                  -{formatRiskReductionScore(reductionIndex)}
                </div>
              </div>
              <div className="dashboard-risk-posture-reducer-meta">
                <div className="dashboard-risk-posture-reducer-meta-line">
                  {index === 0 ? (
                    <span className="dashboard-risk-posture-lever-tag">
                      biggest lever
                    </span>
                  ) : null}
                  <span>{riskReducerMetaLabel(opportunity)}</span>
                  <RiskPostureSignalTags opportunity={opportunity} />
                </div>
                <span className="dashboard-risk-posture-reducer-context">
                  {shortContextList(opportunity.business_services)}
                </span>
              </div>
              <span className="dashboard-risk-posture-reducer-track">
                <span
                  className="dashboard-risk-posture-reducer-track-fill"
                  style={riskPostureStyle(
                    "--risk-posture-reducer-width",
                    `${riskReductionPercent(
                      opportunity.expected_reduction ?? 0,
                      summary.maxOpportunityReduction,
                    )}%`,
                  )}
                />
              </span>
            </li>
          )
        })}
      </ol>
    </section>
  )
}

function RiskPostureSignalTags({
  opportunity,
}: {
  opportunity: RiskReductionOpportunityPublic
}) {
  return (
    <>
      {opportunity.in_kev ? (
        <span className="dashboard-risk-posture-reducer-tag dashboard-risk-posture-reducer-tag--kev">
          KEV
        </span>
      ) : null}
      {opportunity.max_epss !== null && opportunity.max_epss !== undefined ? (
        <span className="dashboard-risk-posture-reducer-tag dashboard-risk-posture-reducer-tag--epss">
          EPSS {Math.round(opportunity.max_epss * 1000) / 10}%
        </span>
      ) : null}
      {opportunity.max_cvss !== null && opportunity.max_cvss !== undefined ? (
        <span className="dashboard-risk-posture-reducer-tag dashboard-risk-posture-reducer-tag--cvss">
          CVSS {formatRiskReductionScore(opportunity.max_cvss)}
        </span>
      ) : null}
    </>
  )
}

function toggleReducer(
  opportunityId: string,
  selectedOpportunityIds: ReadonlySet<string>,
  setSelectedOpportunityIds: (value: Set<string>) => void,
) {
  const next = new Set(selectedOpportunityIds)
  if (next.has(opportunityId)) {
    next.delete(opportunityId)
  } else {
    next.add(opportunityId)
  }
  setSelectedOpportunityIds(next)
}

function opportunityRouteSearch(
  opportunity: {
    component?: string | null
    cve_id: string
    search_query: string
  },
  selectedProjectId: string,
) {
  const query =
    opportunity.search_query ||
    opportunity.cve_id ||
    opportunity.component ||
    ""
  return {
    ...selectedProjectRouteSearch(selectedProjectId),
    ...(query ? { query } : {}),
  }
}

function reducerTitle(opportunity: {
  component?: string | null
  cve_id: string
  label: string
  recommended_action: string
}) {
  const cleanAction = opportunity.recommended_action.replace(/\.$/, "").trim()
  if (
    cleanAction &&
    cleanAction.length <= 58 &&
    !cleanAction.toLowerCase().startsWith("cisa kev")
  ) {
    return cleanAction
  }
  if (opportunity.component) {
    return `Patch ${opportunity.component}`
  }
  return opportunity.label || opportunity.cve_id
}

function chartBarTone(
  step: RiskPostureProjectionStep,
  targetIndex: number,
): "critical" | "low" | "moderate" | "projected" | "success" {
  if (step.mode === "actual") return riskIndexBand(step.riskIndex)
  if (step.riskIndex <= targetIndex) return "success"
  return "projected"
}

function projectionStepDisplayLabel(label: string) {
  switch (label) {
    case "Current":
      return "Now"
    case "After checked top 1":
      return "Top 1"
    case "After checked top 3":
      return "Top 3"
    case "Checked plan":
      return "Plan"
    default:
      return label
  }
}

function riskIndexBand(value: number): "critical" | "low" | "moderate" {
  if (value >= 70) return "critical"
  if (value >= 40) return "moderate"
  return "low"
}

function clamp(value: number) {
  return Math.max(0, Math.min(100, value))
}

function statusCount(
  projectSummary: ProjectDecisionSummaryPublic | null,
  status: string,
) {
  const counts = projectSummary?.counts_by_status
  if (!counts) {
    return 0
  }
  const match = Object.entries(counts).find(
    ([key]) => key.toLowerCase() === status.toLowerCase(),
  )
  return typeof match?.[1] === "number" ? match[1] : 0
}

function riskPostureStyle(variable: string, value: string): CSSProperties {
  return { [variable]: value } as CSSProperties
}
