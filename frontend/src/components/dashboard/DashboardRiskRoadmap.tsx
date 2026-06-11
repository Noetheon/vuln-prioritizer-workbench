import type { MitigationLeverPublic } from "@/api-client"
import {
  groupMitigationLeversByLane,
  RISK_ROADMAP_LANES,
} from "./dashboard-risk-scenario-model"

type DashboardRiskRoadmapProps = {
  levers: readonly MitigationLeverPublic[]
  selectedLeverIds: readonly string[]
}

export function DashboardRiskRoadmap({
  levers,
  selectedLeverIds,
}: DashboardRiskRoadmapProps) {
  const grouped = groupMitigationLeversByLane(levers)
  const selected = new Set(selectedLeverIds)

  return (
    <section aria-label="Risk impact roadmap" className="risk-roadmap">
      <div className="risk-section-heading">
        <span className="risk-micro-label">Impact roadmap</span>
        <span>Now / Next / Later by evidence-backed reduction</span>
      </div>
      <div className="risk-roadmap-lanes">
        {RISK_ROADMAP_LANES.map((lane) => {
          const laneLevers = grouped[lane.id]
          return (
            <section
              className="risk-roadmap-lane"
              data-lane={lane.id}
              key={lane.id}
            >
              <header className="risk-roadmap-lane__header">
                <div>
                  <h3>{lane.label}</h3>
                  <p>{lane.description}</p>
                </div>
                <span className="risk-roadmap-lane__count">
                  {laneLevers.length}
                </span>
              </header>
              {laneLevers.length === 0 ? (
                <p className="risk-roadmap-empty">No current lever in lane</p>
              ) : (
                <ol className="risk-roadmap-items">
                  {laneLevers.map((lever) => (
                    <RiskRoadmapItem
                      key={lever.lever_id}
                      lever={lever}
                      selected={selected.has(lever.lever_id)}
                    />
                  ))}
                </ol>
              )}
            </section>
          )
        })}
      </div>
    </section>
  )
}

function RiskRoadmapItem({
  lever,
  selected,
}: {
  lever: MitigationLeverPublic
  selected: boolean
}) {
  const attackLabel = attackTechniqueLabel(lever)
  return (
    <li className="risk-roadmap-item" data-selected={selected || undefined}>
      <div className="risk-roadmap-item__main">
        <strong className="risk-roadmap-item__title" title={lever.action_label}>
          {lever.action_label}
        </strong>
        <span className="risk-roadmap-item__reason">
          {lever.roadmap_reason || "Ranked by current risk evidence."}
        </span>
      </div>
      <div className="risk-roadmap-item__chips">
        <span className="risk-lever-chip">
          −{formatNumber(lever.risk_score_sum ?? 0)} pts
        </span>
        <span className="risk-lever-chip">
          {lever.resolved_finding_count ?? 0} findings
        </span>
        {(lever.resolved_kev_count ?? 0) > 0 ? (
          <span className="risk-lever-chip risk-lever-chip--kev">
            {lever.resolved_kev_count} KEV
          </span>
        ) : null}
        <span className="risk-lever-chip">
          {lever.nist_csf_function ?? "Unclassified"}
        </span>
        <span className="risk-lever-chip risk-lever-chip--attack">
          {attackLabel}
        </span>
      </div>
    </li>
  )
}

function attackTechniqueLabel(lever: MitigationLeverPublic): string {
  const techniques = lever.attack_techniques ?? []
  if (techniques.length === 0) {
    return "No reviewed ATT&CK mapping"
  }
  return techniques
    .slice(0, 2)
    .map((technique) =>
      technique.name
        ? `${technique.technique_id} ${technique.name}`
        : technique.technique_id,
    )
    .join(", ")
}

function formatNumber(value: number): string {
  return Number.isInteger(value) ? String(value) : value.toFixed(1)
}
