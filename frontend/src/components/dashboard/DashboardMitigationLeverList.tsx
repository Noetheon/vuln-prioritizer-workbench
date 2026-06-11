import type { CSSProperties } from "react"
import type { MitigationLeverPublic } from "@/api-client"
import { Checkbox } from "@/components/ui/checkbox"
import { mitigationLeverChartData, riskScoreBand } from "@/lib/chart-data"
import { ChartDataSummary } from "./DashboardChartShared"

type DashboardMitigationLeverListProps = {
  levers: readonly MitigationLeverPublic[]
  onSelectionChange?: (selectedLeverIds: string[]) => void
  recommendedLeverId?: string | null
  selectedLeverIds?: readonly string[]
  selectable?: boolean
  /** Sum of risk scores across all open findings; enables the share chip. */
  totalOpenRiskScore?: number | null
}

export function DashboardMitigationLeverList({
  levers,
  onSelectionChange,
  recommendedLeverId = null,
  selectedLeverIds = [],
  selectable = false,
  totalOpenRiskScore = null,
}: DashboardMitigationLeverListProps) {
  const maxSum = Math.max(
    ...levers.map((lever) => lever.risk_score_sum ?? 0),
    1,
  )
  const selected = new Set(selectedLeverIds)
  const toggleLever = (leverId: string, checked: boolean | "indeterminate") => {
    if (!onSelectionChange) {
      return
    }
    const current = new Set(selectedLeverIds)
    if (checked === true) {
      current.add(leverId)
    } else {
      current.delete(leverId)
    }
    const ordered = levers
      .map((lever) => lever.lever_id)
      .filter((leverId) => current.has(leverId))
    onSelectionChange(ordered)
  }
  return (
    <>
      <ol className="risk-lever-list">
        {levers.map((lever, index) => {
          const sum = lever.risk_score_sum ?? 0
          const count = lever.resolved_finding_count ?? 0
          const kev = lever.resolved_kev_count ?? 0
          const tone = riskScoreBand(count > 0 ? sum / count : sum)
          const share =
            lever.risk_score_share_percent ?? leverShare(sum, totalOpenRiskScore)
          const note = leverProjectionNote(lever)
          const checked = selected.has(lever.lever_id)
          const leverKey = lever.lever_id || lever.action_label
          return (
            <li
              className={`risk-lever-row risk-tone ${
                selectable ? "risk-lever-row--selectable" : ""
              }`}
              data-selected={checked || undefined}
              data-tone={tone}
              key={leverKey}
              style={{ "--risk-lever-index": index } as CSSProperties}
            >
              {selectable ? (
                <Checkbox
                  aria-label={`Include ${lever.action_label} in risk scenario`}
                  checked={checked}
                  className="risk-lever-checkbox"
                  onCheckedChange={(nextChecked) =>
                    toggleLever(lever.lever_id, nextChecked)
                  }
                />
              ) : null}
              <span aria-hidden="true" className="risk-lever-rank">
                {String(index + 1).padStart(2, "0")}
              </span>
              <span className="risk-lever-action" title={lever.action_label}>
                {lever.action_label}
              </span>
              <span className="risk-lever-pts">
                −{Math.round(sum)}
                <span className="risk-lever-pts-unit">pts</span>
              </span>
              <span className="risk-lever-detail">
                <span className="risk-lever-chip">
                  {count} {count === 1 ? "finding" : "findings"}
                </span>
                {kev > 0 ? (
                  <span className="risk-lever-chip risk-lever-chip--kev">
                    {kev} KEV
                  </span>
                ) : null}
                {share !== null ? (
                  <span className="risk-lever-chip">
                    {share}% of open risk
                  </span>
                ) : null}
                {lever.lever_id === recommendedLeverId ? (
                  <span className="risk-lever-chip risk-lever-chip--recommended">
                    Recommended
                  </span>
                ) : null}
                <span className="risk-lever-chip">
                  {roadmapLaneLabel(lever.roadmap_lane)}
                </span>
                <span className="risk-lever-chip">
                  {lever.nist_csf_function ?? "Unclassified"}
                </span>
                <span className="risk-lever-chip risk-lever-chip--attack">
                  {attackTechniqueLabel(lever)}
                </span>
                {note ? <span className="risk-lever-note">{note}</span> : null}
              </span>
              <span aria-hidden="true" className="risk-lever-track">
                <span
                  className="risk-lever-fill"
                  style={{ width: `${Math.max(4, (sum / maxSum) * 100)}%` }}
                />
              </span>
            </li>
          )
        })}
      </ol>
      <ChartDataSummary
        data={mitigationLeverChartData(levers)}
        label="Mitigation levers chart data"
      />
    </>
  )
}

function leverShare(
  sum: number,
  totalOpenRiskScore: number | null | undefined,
): number | null {
  if (!totalOpenRiskScore || totalOpenRiskScore <= 0) {
    return null
  }
  return Math.min(100, Math.round((sum / totalOpenRiskScore) * 100))
}

function roadmapLaneLabel(value: string | null | undefined): string {
  if (value === "now") {
    return "Now"
  }
  if (value === "next") {
    return "Next"
  }
  return "Later"
}

function attackTechniqueLabel(lever: MitigationLeverPublic): string {
  const techniques = lever.attack_techniques ?? []
  if (techniques.length === 0) {
    return "No reviewed ATT&CK mapping"
  }
  const first = techniques[0]
  return first.name ? `${first.technique_id} ${first.name}` : first.technique_id
}

function leverProjectionNote(lever: MitigationLeverPublic): string | null {
  const projected = lever.projected_average_risk_score ?? null
  if (projected === null) {
    return "clears all open findings"
  }
  const delta = lever.average_delta ?? null
  // A near-zero shift is noise (e.g. saturated demo data) — stay quiet.
  if (delta === null || Math.abs(delta) < 0.5) {
    return null
  }
  const direction = delta > 0 ? "−" : "+"
  return `avg → ${projected} (${direction}${Math.abs(delta)})`
}
