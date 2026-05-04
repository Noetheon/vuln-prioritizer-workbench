import {
  VpwBadge,
  VpwGrid,
  VpwProgress,
  VpwSection,
  VpwSectionHeader,
  VpwSelectionCard,
} from "../vpw"
import {
  exposureTone,
  type ServiceRollup,
} from "./asset-model"
import { formatLabel as labelize } from "../../lib/ui-copy"

export function AssetServiceRollup({
  serviceRollups,
  setAssetServiceFilter,
}: {
  serviceRollups: ServiceRollup[]
  setAssetServiceFilter: (value: string) => void
}) {
  if (serviceRollups.length === 0) {
    return null
  }

  return (
    <VpwSection>
      <VpwSectionHeader
        description="Rollup by business service and owner for faster exposure review."
        eyebrow="Service exposure"
        title="Service and owner rollup"
      />
      <VpwGrid columns={1} className="lg:grid-cols-2 xl:grid-cols-4">
        {serviceRollups.slice(0, 8).map((rollup) => (
          <VpwSelectionCard
            key={rollup.id}
            meta={`${rollup.assetCount} assets - ${rollup.findings} findings`}
            onClick={() => setAssetServiceFilter(rollup.label)}
            title={rollup.label}
          >
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2">
                <VpwBadge tone="support">{rollup.owner}</VpwBadge>
                <VpwBadge tone={exposureTone(rollup.exposure)}>
                  {labelize(rollup.exposure)}
                </VpwBadge>
                <VpwBadge
                  tone={rollup.criticalAssets > 0 ? "warning" : "success"}
                >
                  {rollup.criticalAssets} critical/high
                </VpwBadge>
              </div>
              <VpwProgress
                label="Evidence readiness"
                tone={rollup.findings > 0 ? "info" : "neutral"}
                value={rollup.findings > 0 ? 66 : 20}
              />
            </div>
          </VpwSelectionCard>
        ))}
      </VpwGrid>
    </VpwSection>
  )
}
