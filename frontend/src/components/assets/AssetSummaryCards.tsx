import { Globe2, Link2, RefreshCw, Server, ShieldCheck } from "lucide-react"
import type { ReactNode } from "react"

import { VpwCompactMetric, VpwMetricStrip } from "../vpw"
import type { AssetSummary } from "./asset-model"

export function AssetSummaryCards({
  assetSummary,
}: {
  assetSummary: AssetSummary
}) {
  return (
    <VpwMetricStrip
      aria-label="Asset summary"
      className="assets-kpi-strip"
      minCardWidth="11.5rem"
    >
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
    </VpwMetricStrip>
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
    <VpwCompactMetric
      description={description}
      icon={icon}
      label={label}
      tone={tone}
      value={value}
    />
  )
}
