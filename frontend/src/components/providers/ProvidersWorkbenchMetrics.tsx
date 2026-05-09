import {
  Archive,
  Clock3,
  Database,
  FileArchive,
  ShieldCheck,
  Signal,
} from "lucide-react"

import type { ProviderStatusPublic } from "@/api-client"
import { VpwGrid, VpwMetricCard } from "@/components/vpw"
import {
  formatCacheAge,
  providerSnapshotHealth,
  providerSnapshotSummary,
} from "@/lib/provider-format"
import {
  dataQualityLabel,
  evidenceReadinessLabel,
  evidenceReadinessTone,
  formatDateTime,
  type ProviderSourceCounts,
  providerHealthTone,
} from "./providers-workbench-model"

type ProviderMetricsGridProps = {
  counts: ProviderSourceCounts
  providerStatus: ProviderStatusPublic | null
}

export function ProviderMetricsGrid({
  counts,
  providerStatus,
}: ProviderMetricsGridProps) {
  const dataQuality = dataQualityLabel(providerStatus)
  const evidenceReadiness = evidenceReadinessLabel(providerStatus)

  return (
    <VpwGrid
      className="md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6"
      columns={1}
    >
      <VpwMetricCard
        description={providerSnapshotSummary(providerStatus)}
        icon={<Signal aria-hidden="true" />}
        label="Provider health"
        tone={providerHealthTone(providerStatus)}
        value={providerSnapshotHealth(providerStatus)}
      />
      <VpwMetricCard
        description={
          providerStatus?.snapshot.locked_provider_data
            ? "Locked replay evidence"
            : "Stored provider evidence"
        }
        icon={<Archive aria-hidden="true" />}
        label="Snapshot mode"
        tone={
          providerStatus?.snapshot.locked_provider_data ? "support" : "info"
        }
        value={providerStatus?.snapshot_mode ?? "missing"}
      />
      <VpwMetricCard
        description="Latest provider snapshot update"
        icon={<Clock3 aria-hidden="true" />}
        label="Last sync"
        value={formatDateTime(providerStatus?.last_sync)}
      />
      <VpwMetricCard
        description="Age of stored provider cache"
        icon={<Database aria-hidden="true" />}
        label="Cache age"
        value={formatCacheAge(providerStatus?.cache_age_seconds)}
      />
      <VpwMetricCard
        description={`${counts.missingSources} missing, ${counts.staleSources} stale`}
        icon={<ShieldCheck aria-hidden="true" />}
        label="Data quality"
        tone={counts.missingSources > 0 ? "warning" : "success"}
        value={dataQuality}
      />
      <VpwMetricCard
        description="Provider data for reports"
        icon={<FileArchive aria-hidden="true" />}
        label="Evidence readiness"
        tone={evidenceReadinessTone(providerStatus)}
        value={evidenceReadiness}
      />
    </VpwGrid>
  )
}
