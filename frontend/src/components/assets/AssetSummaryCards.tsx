import { Globe2, Link2, RefreshCw, Server, ShieldCheck } from "lucide-react"
import type { ReactNode } from "react"

import type { AssetSummary } from "./asset-model"

export function AssetSummaryCards({
  assetSummary,
}: {
  assetSummary: AssetSummary
}) {
  return (
    <section aria-label="Asset summary" className="assets-kpi-strip">
      <AssetKpi
        description="Assets and target references in scope"
        icon={<Server aria-hidden="true" />}
        label="Total assets"
        value={assetSummary.total}
      />
      <AssetKpi
        description="External exposure"
        icon={<Globe2 aria-hidden="true" />}
        label="Internet-facing"
        tone="warning"
        value={assetSummary.internetFacing}
      />
      <AssetKpi
        description="Critical or high context"
        icon={<ShieldCheck aria-hidden="true" />}
        label="Critical services"
        tone="critical"
        value={assetSummary.criticalServices}
      />
      <AssetKpi
        description="Associated findings"
        icon={<Link2 aria-hidden="true" />}
        label="Linked findings"
        tone="info"
        value={assetSummary.linkedFindings}
      />
      <AssetKpi
        description={`${assetSummary.ownerCoverage}% owner coverage; ${assetSummary.production} production assets`}
        icon={<RefreshCw aria-hidden="true" />}
        label="Rescore needed"
        tone={assetSummary.rescoreNeeded > 0 ? "warning" : "success"}
        value={assetSummary.rescoreNeeded}
      />
    </section>
  )
}

function AssetKpi({
  description,
  icon,
  label,
  tone = "neutral",
  value,
}: {
  description: string
  icon: ReactNode
  label: string
  tone?: "neutral" | "success" | "warning" | "critical" | "info"
  value: ReactNode
}) {
  return (
    <div className="assets-kpi-card" data-tone={tone}>
      <span className="assets-kpi-card__icon">{icon}</span>
      <div className="assets-kpi-card__body">
        <span className="vpw-label">{label}</span>
        <strong>{value}</strong>
        <small>{description}</small>
      </div>
    </div>
  )
}
