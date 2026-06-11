import { RotateCcw, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import type { RiskScenario } from "./dashboard-risk-scenario-model"

type DashboardRiskScenarioPanelProps = {
  canReset: boolean
  onClearSelection: () => void
  onResetSelection: () => void
  scenario: RiskScenario
}

export function DashboardRiskScenarioPanel({
  canReset,
  onClearSelection,
  onResetSelection,
  scenario,
}: DashboardRiskScenarioPanelProps) {
  const hasSelection = scenario.selectedLevers.length > 0
  const targetMet =
    scenario.targetGap !== null &&
    scenario.projectedAverageRiskScore !== null &&
    scenario.targetGap <= 0

  return (
    <section className="risk-scenario-panel" aria-label="Risk what-if scenario">
      <div className="risk-scenario-panel__header">
        <div>
          <span className="risk-micro-label">What-if impact</span>
          <h3>Selected mitigation scenario</h3>
        </div>
        <div className="risk-scenario-actions">
          <Button
            disabled={!canReset}
            onClick={onResetSelection}
            size="sm"
            type="button"
            variant="ghost"
          >
            <RotateCcw aria-hidden="true" className="size-3.5" />
            Recommended
          </Button>
          <Button
            disabled={!hasSelection}
            onClick={onClearSelection}
            size="sm"
            type="button"
            variant="ghost"
          >
            <X aria-hidden="true" className="size-3.5" />
            Clear
          </Button>
        </div>
      </div>
      <div className="risk-scenario-metrics">
        <div className="risk-scenario-metric risk-tone" data-tone="critical">
          <span className="risk-micro-label">Risk removed</span>
          <strong className="risk-scenario-metric__value">
            −{formatNumber(scenario.riskRemovedScore)}
            <small className="risk-scenario-metric__unit">pts</small>
          </strong>
          <span className="risk-scenario-metric__detail">
            {scenario.riskRemovedPercent}% of current open risk
          </span>
        </div>
        <div className="risk-scenario-metric">
          <span className="risk-micro-label">Projected avg</span>
          <strong className="risk-scenario-metric__value">
            {formatNullableScore(scenario.projectedAverageRiskScore)}
            <small className="risk-scenario-metric__unit">/ 100</small>
          </strong>
          <span className="risk-scenario-metric__detail">
            {scenario.averageDelta === null
              ? "No baseline average available"
              : scenario.averageDelta >= 0
                ? `down ${formatNumber(scenario.averageDelta)} avg points`
                : `up ${formatNumber(Math.abs(scenario.averageDelta))} avg points`}
          </span>
        </div>
        <div
          className="risk-scenario-metric"
          data-state={targetMet ? "met" : "open"}
        >
          <span className="risk-micro-label">Target</span>
          <strong className="risk-scenario-metric__value">
            {targetMet ? "met" : formatGap(scenario.targetGap)}
            <small className="risk-scenario-metric__unit">
              {targetMet ? "" : "pts over"}
            </small>
          </strong>
          <span className="risk-scenario-metric__detail">
            target avg {formatNumber(scenario.riskTargetScore)}
          </span>
        </div>
      </div>
      <div className="risk-scenario-foot">
        <span>
          {scenario.totalFindingsResolved} findings resolved
          {scenario.kevResolved > 0 ? ` · ${scenario.kevResolved} KEV` : ""}
        </span>
        <span>
          {scenario.clearsAllFindings
            ? "All open findings covered by selected levers"
            : `${scenario.remainingOpenFindingCount} findings remain · ${formatNumber(
                scenario.remainingRiskScore,
              )} pts`}
        </span>
      </div>
    </section>
  )
}

function formatGap(value: number | null): string {
  if (value === null) {
    return "—"
  }
  return formatNumber(Math.max(0, value))
}

function formatNullableScore(value: number | null): string {
  return value === null ? "—" : formatNumber(value)
}

function formatNumber(value: number): string {
  return Number.isInteger(value) ? String(value) : value.toFixed(1)
}
