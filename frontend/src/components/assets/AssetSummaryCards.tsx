import { Globe2, Link2, RefreshCw, Server, ShieldCheck } from "lucide-react"

import { VpwGrid, VpwMetricCard } from "../vpw"
import type { AssetSummary } from "./asset-model"

export function AssetSummaryCards({
  assetSummary,
}: {
  assetSummary: AssetSummary
}) {
  return (
    <VpwGrid columns={1} className="lg:grid-cols-2 xl:grid-cols-5">
      <VpwMetricCard
        description="Assets and target references in scope"
        icon={<Server aria-hidden="true" />}
        label="Total assets"
        value={assetSummary.total}
      />
      <VpwMetricCard
        description="Assets with external exposure"
        icon={<Globe2 aria-hidden="true" />}
        label="Internet-facing"
        tone="warning"
        value={assetSummary.internetFacing}
      />
      <VpwMetricCard
        description="Critical and high asset context"
        icon={<ShieldCheck aria-hidden="true" />}
        label="Critical services"
        tone="critical"
        value={assetSummary.criticalServices}
      />
      <VpwMetricCard
        description="Findings associated with asset context"
        icon={<Link2 aria-hidden="true" />}
        label="Linked findings"
        tone="info"
        value={assetSummary.linkedFindings}
      />
      <VpwMetricCard
        description={`${assetSummary.ownerCoverage}% owner coverage; ${assetSummary.production} production assets`}
        icon={<RefreshCw aria-hidden="true" />}
        label="Rescore needed"
        tone={assetSummary.rescoreNeeded > 0 ? "warning" : "success"}
        value={assetSummary.rescoreNeeded}
      />
    </VpwGrid>
  )
}
