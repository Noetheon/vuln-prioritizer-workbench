import { CountBadge, MetaTag, VpwSection, VpwTableCard } from "../vpw"
import type { ServiceRollup } from "./asset-model"
import { formatLabel as labelize } from "../../lib/ui-copy"
import { Button } from "../ui/button"

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
      <VpwTableCard
        className="asset-service-rollup"
        description="Top service groups by asset count and linked finding pressure. Use a row to filter the register."
        eyebrow="Secondary analysis"
        title="Service focus"
      >
        <div className="asset-service-rollup__list">
          <div
            aria-hidden="true"
            className="asset-service-rollup__row asset-service-rollup__row--header"
          >
            <span>Service</span>
            <span>Owner</span>
            <span>Exposure</span>
            <span>Assets</span>
            <span>Findings</span>
            <span>Critical/high</span>
            <span>Action</span>
          </div>
          {serviceRollups.slice(0, 8).map((rollup) => (
            <div className="asset-service-rollup__row" key={rollup.id}>
              <div className="asset-service-rollup__primary">
                <strong>{rollup.label}</strong>
                <span>{`${rollup.assetCount} assets - ${rollup.findings} findings`}</span>
              </div>
              <MetaTag label={rollup.owner} />
              <MetaTag label={labelize(rollup.exposure)} />
              <CountBadge value={rollup.assetCount} />
              <CountBadge
                tone={rollup.findings > 0 ? "info" : "success"}
                value={rollup.findings}
              />
              <CountBadge
                tone={rollup.criticalAssets > 0 ? "warning" : "success"}
                value={rollup.criticalAssets}
              />
              <Button
                onClick={() => setAssetServiceFilter(rollup.label)}
                size="sm"
                type="button"
                variant="outline"
              >
                Filter
              </Button>
            </div>
          ))}
        </div>
      </VpwTableCard>
    </VpwSection>
  )
}
