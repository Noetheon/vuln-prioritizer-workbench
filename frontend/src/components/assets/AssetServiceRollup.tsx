import {
  CountBadge,
  MetaTag,
  VpwGrid,
  VpwProgress,
  VpwSection,
  VpwSelectionCard,
} from "../vpw"
import type { ServiceRollup } from "./asset-model"
import { formatLabel as labelize } from "../../lib/ui-copy"
import { ChevronDown } from "lucide-react"

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
      <details className="group rounded-[var(--vpw-radius-xl)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] shadow-[var(--vpw-shadow-0)]">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-5 py-4 [&::-webkit-details-marker]:hidden">
          <span>
            <span className="vpw-label text-[var(--vpw-teal)]">
              Service exposure
            </span>
            <span className="mt-1 block text-base font-semibold text-[var(--vpw-text-primary)]">
              Service and owner rollup
            </span>
            <span className="mt-1 block text-sm text-[var(--vpw-text-secondary)]">
              Rollup by business service and owner for faster exposure review.
            </span>
          </span>
          <ChevronDown
            aria-hidden="true"
            className="size-4 shrink-0 text-[var(--vpw-text-muted)] transition-transform group-open:rotate-180"
          />
        </summary>
        <div className="border-t border-[var(--vpw-border-subtle)] p-5">
          <VpwGrid columns={1} className="lg:grid-cols-2 xl:grid-cols-4">
            {serviceRollups.slice(0, 8).map((rollup) => (
              <VpwSelectionCard
                key={rollup.id}
                meta={`${rollup.assetCount} assets - ${rollup.findings} findings`}
                onClick={() => setAssetServiceFilter(rollup.label)}
                title={rollup.label}
              >
                <div className="flex flex-col gap-3">
                  <div className="flex flex-wrap gap-2">
                    <MetaTag label={rollup.owner} />
                    <MetaTag label={labelize(rollup.exposure)} />
                    <CountBadge
                      label={`${rollup.criticalAssets} critical/high`}
                      tone={rollup.criticalAssets > 0 ? "warning" : "success"}
                      value={rollup.criticalAssets}
                    />
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
        </div>
      </details>
    </VpwSection>
  )
}
