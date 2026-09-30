import {
  ArrowUpRight,
  CheckSquare2,
  ShieldCheck,
  Square,
  Target,
  TrendingDown,
} from "lucide-react"
import type { CSSProperties } from "react"
import { useEffect, useMemo, useRef, useState } from "react"

import type {
  ProjectDecisionSummaryPublic,
  ProjectRiskKpisPublic,
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
import { DashboardOpportunityScope } from "./DashboardOpportunityScope"
import {
  buildRiskPostureHistorySteps,
  buildRiskPostureProjection,
  buildRiskReductionSummary,
  formatRiskReductionScore,
  type RiskPostureHistoryStep,
  type RiskPostureProjectionStep,
  type RiskReductionSummary,
  riskReducerMetaLabel,
  riskReductionPercent,
  selectedRiskPostureReducers,
  shortContextList,
} from "./dashboard-risk-reduction-model"

type DashboardRiskReductionPanelProps = {
  isLoading: boolean
  kpis?: ProjectRiskKpisPublic | null
  projectSummary: ProjectDecisionSummaryPublic | null
  riskReduction: ProjectRiskReductionPublic | null
  selectedProjectId: string
}

export function DashboardRiskReductionPanel({
  isLoading,
  kpis = null,
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
  const checkedReduction = checkedPlan?.reductionScore ?? 0

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
              checkedReduction={checkedReduction}
              kpis={kpis}
              projectSummary={projectSummary}
              summary={summary}
            />
            <RiskPostureProjection
              band={openRiskBand(kpis)}
              currentRisk={summary.currentRisk}
              historySteps={historySteps}
              projection={projection}
              selectedCount={selectedOpportunityIds.size}
              targetRisk={summary.targetRisk}
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
      {!isLoading ? (
        <details className="mx-5 mb-4 text-xs text-[var(--vpw-text-secondary)]">
          <summary className="cursor-pointer">
            How this metric and simulation work
          </summary>
          <p className="mt-2 max-w-4xl leading-5">{summary.methodology}</p>
        </details>
      ) : null}
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
  checkedReduction,
  kpis,
  projectSummary,
  summary,
}: {
  checkedReduction: number
  kpis: ProjectRiskKpisPublic | null
  projectSummary: ProjectDecisionSummaryPublic | null
  summary: RiskReductionSummary
}) {
  const band = openRiskBand(kpis)
  const openFindingCount = kpis?.open_findings ?? summary.actionableFindingCount
  const acceptedCount =
    kpis?.accepted_findings ?? statusCount(projectSummary, "accepted")
  return (
    <section
      aria-label="Open risk summary"
      className="dashboard-risk-posture-summary"
    >
      <div className="dashboard-risk-posture-summary-kicker">
        Open risk · sum of open finding scores
      </div>
      <div
        className={`dashboard-risk-posture-index dashboard-risk-posture-index--${band}`}
      >
        {formatRiskReductionScore(summary.currentRisk)}
      </div>
      <div className="dashboard-risk-posture-index-change">
        <TrendingDown aria-hidden="true" className="size-4" />
        <span className="dashboard-risk-posture-index-change-value">
          {formatRiskReductionScore(checkedReduction)}
        </span>
        <span className="dashboard-risk-posture-index-change-label">
          removed by the checked plan
        </span>
      </div>
      <dl aria-label="Open work KPIs" className="dashboard-risk-posture-kpis">
        {riskPostureFacts(kpis).map((fact) => (
          <div className="dashboard-risk-posture-kpi" key={fact.label}>
            <dt>{fact.label}</dt>
            <dd>{fact.value}</dd>
          </div>
        ))}
      </dl>
      <RiskPostureSeverityStrip kpis={kpis} projectSummary={projectSummary} />
      <div className="dashboard-risk-posture-scope-line">
        <span className="dashboard-risk-posture-scope-item">
          Average score {formatRiskReductionScore(summary.currentRiskIndex)}{" "}
          across {formatRiskReductionScore(openFindingCount)} open findings
        </span>
        <span
          className="dashboard-risk-posture-scope-item"
          title="Accepted findings are not open work; their score is shown separately."
        >
          {formatRiskReductionScore(acceptedCount)} accepted (
          {formatRiskReductionScore(
            kpis?.accepted_risk ?? summary.governanceDebtRisk,
          )}{" "}
          score)
        </span>
      </div>
    </section>
  )
}

function riskPostureFacts(kpis: ProjectRiskKpisPublic | null) {
  const window = kpis?.closure_window_days ?? 90
  const compliance = kpis?.sla_compliance_rate
  const mttr = kpis?.mttr_days
  return [
    { label: "Open critical", value: String(kpis?.open_critical ?? 0) },
    { label: "Open KEV", value: String(kpis?.open_kev ?? 0) },
    { label: "Overdue", value: String(kpis?.overdue ?? 0) },
    {
      label: `SLA met (${window} d)`,
      value:
        compliance === null || compliance === undefined
          ? "No closures"
          : `${Math.round(compliance * 100)}%`,
    },
    {
      label: `MTTR (${window} d)`,
      value:
        mttr === null || mttr === undefined
          ? "No closures"
          : `${formatRiskReductionScore(mttr)} d`,
    },
  ]
}

function RiskPostureSeverityStrip({
  kpis,
  projectSummary,
}: {
  kpis: ProjectRiskKpisPublic | null
  projectSummary: ProjectDecisionSummaryPublic | null
}) {
  const buckets = findingsByPriorityChartData(
    kpis
      ? ({
          counts_by_priority: kpis.open_by_priority ?? {},
        } as ProjectDecisionSummaryPublic)
      : projectSummary,
  )
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
  key: string
  label: string
  remainingFindings: number | null
  riskScore: number
  tone: "critical" | "history" | "low" | "moderate" | "projected" | "success"
}

function RiskPostureProjection({
  band,
  currentRisk,
  historySteps,
  projection,
  selectedCount,
  targetRisk,
}: {
  band: OpenRiskBand
  currentRisk: number
  historySteps: readonly RiskPostureHistoryStep[]
  projection: readonly RiskPostureProjectionStep[]
  selectedCount: number
  targetRisk: number
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
  // Runs recorded before absolute open risk was kept have no bar.
  const recordedHistory = historySteps.filter(
    (step): step is RiskPostureHistoryStep & { openRisk: number } =>
      step.openRisk !== null,
  )
  const scaleMax = Math.max(
    currentRisk,
    ...recordedHistory.map((step) => step.openRisk),
    1,
  )
  const chartScale = plotHeight / scaleMax
  const chartLeft = 56
  const chartRight = viewBoxWidth - 16
  const todayGap = 38
  const ticks = [1, 0.75, 0.5, 0.25, 0].map((share) => ({
    share,
    value: Math.round(scaleMax * share),
  }))
  const allBars: RiskPostureChartBar[] = [
    ...recordedHistory.map((step) => ({
      key: step.key,
      label: step.label,
      remainingFindings: null,
      riskScore: step.openRisk,
      tone: "history" as const,
    })),
    ...projection.map((step) => ({
      key: step.key,
      label: projectionStepDisplayLabel(step.label),
      remainingFindings: step.remainingFindingCount,
      riskScore: step.riskScore,
      tone: chartBarTone(step, targetRisk, band),
    })),
  ]
  // The dashed divider separates persisted runs from the live state; with
  // no history it still separates "Current" from the simulated plan.
  const dividerIndex = recordedHistory.length > 0 ? recordedHistory.length : 1
  const slotWidth =
    allBars.length > 0
      ? (chartRight - chartLeft - todayGap) / allBars.length
      : 0
  const barWidth = Math.round(Math.min(108, Math.max(34, slotWidth * 0.56)))
  const barCenterAt = (index: number) =>
    chartLeft +
    slotWidth * index +
    slotWidth / 2 +
    (index >= dividerIndex ? todayGap : 0)
  const chartBars = allBars.map((bar, index) => ({
    ...bar,
    center: barCenterAt(index),
    height: Math.max(0, Math.min(bar.riskScore, scaleMax)) * chartScale,
    x: barCenterAt(index) - barWidth / 2,
  }))
  const activeStep =
    chartBars.find((bar) => bar.key === activeStepKey) ??
    chartBars[chartBars.length - 1] ??
    null
  const targetY = chartBottom - Math.min(targetRisk, scaleMax) * chartScale
  const todayX = chartLeft + slotWidth * dividerIndex + todayGap / 2
  const historyCaptionX =
    recordedHistory.length > 1
      ? (barCenterAt(0) + barCenterAt(recordedHistory.length - 1)) / 2
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
          aria-label="Scenario projection of open risk"
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
            ).map((tone) => (
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
            ))}
          </defs>
          {ticks.map(({ share, value: tick }) => {
            const y = chartBottom - tick * chartScale
            return (
              <g key={share}>
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
            TARGET {formatRiskReductionScore(targetRisk)}
          </text>
          {chartBars.map((bar) => {
            const isActive = activeStep?.key === bar.key
            const barTop = chartBottom - bar.height
            return (
              <g
                aria-label={`${bar.label}: open risk ${formatRiskReductionScore(
                  bar.riskScore,
                )}${
                  bar.remainingFindings !== null
                    ? `, ${bar.remainingFindings} open findings`
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
                  {formatRiskReductionScore(bar.riskScore)}
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
        currentRisk={currentRisk}
        projection={projection}
        selectedCount={selectedCount}
        targetRisk={targetRisk}
      />
    </section>
  )
}

function RiskPosturePlanReadout({
  currentRisk,
  projection,
  selectedCount,
  targetRisk,
}: {
  currentRisk: number
  projection: readonly RiskPostureProjectionStep[]
  selectedCount: number
  targetRisk: number
}) {
  const finalStep = projection[projection.length - 1] ?? null
  const finalRisk = finalStep?.riskScore ?? currentRisk
  const changePercent =
    currentRisk > 0
      ? Math.round(((finalRisk - currentRisk) / currentRisk) * 100)
      : 0
  const reachedStep = projection.find((step) => step.riskScore <= targetRisk)
  return (
    <div className="dashboard-risk-posture-readout">
      <span className="dashboard-risk-posture-readout-chip">
        {selectedCount} action{selectedCount === 1 ? "" : "s"} planned
      </span>
      <span className="dashboard-risk-posture-readout-text">
        Completing the checked plan takes open risk{" "}
        <strong>
          {formatRiskReductionScore(currentRisk)} →{" "}
          {formatRiskReductionScore(finalRisk)}
        </strong>{" "}
        ({changePercent > 0 ? "+" : ""}
        {changePercent}%); {finalStep?.remainingFindingCount ?? 0} open
        findings remain.
        {reachedStep ? (
          <>
            {" "}
            Target (half of today) reached{" "}
            <strong>{planReadoutStepLabel(reachedStep)}</strong>.
          </>
        ) : (
          <>
            {" "}
            <strong className="dashboard-risk-posture-readout-warn">
              Target (half of today) not reached
            </strong>
            ; add more actions.
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
                  <DashboardOpportunityScope
                    className="dashboard-risk-posture-reducer-link"
                    opportunity={opportunity}
                    selectedProjectId={selectedProjectId}
                  >
                    {reducerTitle(opportunity)}
                  </DashboardOpportunityScope>
                </div>
                <div className="dashboard-risk-posture-reducer-impact">
                  -{formatRiskReductionScore(opportunity.expected_reduction)}
                  <span className="sr-only"> score burden</span>
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

type OpenRiskBand = "critical" | "low" | "moderate"

/** Band by what is open, not by an average that low findings dilute. */
function openRiskBand(kpis: ProjectRiskKpisPublic | null): OpenRiskBand {
  if (!kpis) return "moderate"
  if ((kpis.open_kev ?? 0) > 0 || (kpis.open_critical ?? 0) > 0) {
    return "critical"
  }
  if ((kpis.open_high ?? 0) > 0) return "moderate"
  return "low"
}

function chartBarTone(
  step: RiskPostureProjectionStep,
  targetRisk: number,
  band: OpenRiskBand,
): "critical" | "low" | "moderate" | "projected" | "success" {
  if (step.mode === "actual") return band
  if (step.riskScore <= targetRisk) return "success"
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
