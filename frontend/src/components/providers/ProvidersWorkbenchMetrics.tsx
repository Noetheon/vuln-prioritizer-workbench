import {
  Database,
  FileCheck2,
  LockKeyhole,
  FileArchive,
  Signal,
} from "lucide-react"

import type { ProviderStatusPublic } from "@/api-client"
import { VpwGrid, VpwMetricCard } from "@/components/vpw"
import {
  evidenceReadinessCardTone,
  evidenceReadinessLabel,
  providerFreshnessDetail,
  providerFreshnessLabel,
  providerFreshnessTone,
  providerHealthDescription,
  providerHealthLabel,
  providerHealthTone,
  snapshotModeDescription,
  snapshotModeLabel,
} from "./providers-workbench-model"

type ProviderMetricsGridProps = {
  providerStatus: ProviderStatusPublic | null
}

export function ProviderMetricsGrid({ providerStatus }: ProviderMetricsGridProps) {
  return (
    <VpwGrid columns={4}>
      <VpwMetricCard
        description={providerHealthDescription(providerStatus)}
        icon={<Signal aria-hidden="true" />}
        label="Provider health"
        tone={providerHealthTone(providerStatus)}
        value={providerHealthLabel(providerStatus)}
      />
      <VpwMetricCard
        description={providerFreshnessDetail(providerStatus)}
        icon={<Database aria-hidden="true" />}
        label="Freshness"
        tone={providerFreshnessTone(providerStatus)}
        value={providerFreshnessLabel(providerStatus)}
      />
      <VpwMetricCard
        description={snapshotModeDescription(providerStatus)}
        icon={<LockKeyhole aria-hidden="true" />}
        label="Snapshot mode"
        tone={
          providerStatus?.snapshot.locked_provider_data ? "support" : "info"
        }
        value={snapshotModeLabel(providerStatus)}
      />
      <VpwMetricCard
        description="Provider metadata can be attached to evidence bundles where available."
        icon={
          providerStatus?.last_error ? (
            <FileArchive aria-hidden="true" />
          ) : (
            <FileCheck2 aria-hidden="true" />
          )
        }
        label="Evidence readiness"
        tone={evidenceReadinessCardTone(providerStatus)}
        value={evidenceReadinessLabel(providerStatus)}
      />
    </VpwGrid>
  )
}
