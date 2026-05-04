import { Globe2, Server, ShieldCheck, Users } from "lucide-react"

import { VpwGrid, VpwMetricCard } from "../vpw"
import type { AssetSummary } from "./asset-model"

export function AssetSummaryCards({
  assetSummary,
}: {
  assetSummary: AssetSummary
}) {
  return (
    <VpwGrid columns={1} className="lg:grid-cols-2 xl:grid-cols-4">
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
        description="Production environment context"
        icon={<ShieldCheck aria-hidden="true" />}
        label="Production assets"
        tone="info"
        value={assetSummary.production}
      />
      <VpwMetricCard
        description={`${assetSummary.ownerCoverage}% of assets have an owner`}
        icon={<Users aria-hidden="true" />}
        label="Owner coverage"
        tone="support"
        value={`${assetSummary.ownerCoverage}%`}
      />
    </VpwGrid>
  )
}
