import { Link } from "@/lib/router"
import type { RiskTopDriverPublic } from "@/api-client"
import { riskScoreBand } from "@/lib/chart-data"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"

export function DashboardTopDriverStrip({
  driver,
  selectedProjectId,
}: {
  driver: RiskTopDriverPublic | null
  selectedProjectId: string
}) {
  if (!driver) {
    return null
  }
  const score =
    driver.risk_score === null || driver.risk_score === undefined
      ? null
      : Math.round(driver.risk_score)
  const tone = riskScoreBand(score ?? 0)
  const reasons = driver.score_reasons ?? []
  const reasonsPreview = reasons.slice(0, 2).join(" · ")
  const context = [driver.component_label, driver.asset_label]
    .filter(Boolean)
    .join(" · ")
  return (
    <div className="risk-driver-strip risk-tone" data-tone={tone}>
      <div className="risk-driver-headline">
        <span className="risk-micro-label">Top risk driver</span>
        <Link
          className="risk-driver-cve"
          search={selectedProjectRouteSearch(selectedProjectId)}
          to="/findings"
        >
          {driver.cve_id}
        </Link>
        {score !== null ? (
          <span className="risk-score-chip">Score {score}</span>
        ) : null}
        {driver.in_kev ? (
          <span className="risk-lever-chip risk-lever-chip--kev">
            CISA KEV
          </span>
        ) : null}
        {driver.priority ? (
          <span className="risk-band-chip">{driver.priority}</span>
        ) : null}
      </div>
      <div className="risk-driver-meta">
        {context ? (
          <span className="risk-driver-context">{context}</span>
        ) : null}
        {reasonsPreview ? (
          <span className="risk-driver-reason" title={reasons.join(" · ")}>
            {reasonsPreview}
          </span>
        ) : null}
        {driver.recommended_action ? (
          <span
            className="risk-driver-reason"
            title={driver.recommended_action}
          >
            {driver.recommended_action}
          </span>
        ) : null}
      </div>
    </div>
  )
}
