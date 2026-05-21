import {
  Database,
  FileCheck2,
  LockKeyhole,
  FileArchive,
  Signal,
} from "lucide-react"
import type { ReactNode } from "react"

import type { ProviderStatusPublic } from "@/api-client"
import type { VpwMetricTone } from "@/components/vpw"
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

function ProviderKpiCard({
  description,
  icon,
  label,
  tone,
  value,
}: {
  description: string
  icon: ReactNode
  label: string
  tone: VpwMetricTone
  value: string
}) {
  return (
    <div className="providers-kpi-card" data-tone={tone}>
      <span className="providers-kpi-card__icon">{icon}</span>
      <div className="providers-kpi-card__body">
        <span className="vpw-label">{label}</span>
        <strong>{value}</strong>
        <small title={description}>{description}</small>
      </div>
    </div>
  )
}

export function ProviderMetricsGrid({
  providerStatus,
}: ProviderMetricsGridProps) {
  return (
    <section aria-label="Provider summary" className="providers-kpi-strip">
      <ProviderKpiCard
        description={providerHealthDescription(providerStatus)}
        icon={<Signal aria-hidden="true" />}
        label="Provider health"
        tone={providerHealthTone(providerStatus)}
        value={providerHealthLabel(providerStatus)}
      />
      <ProviderKpiCard
        description={providerFreshnessDetail(providerStatus)}
        icon={<Database aria-hidden="true" />}
        label="Freshness"
        tone={providerFreshnessTone(providerStatus)}
        value={providerFreshnessLabel(providerStatus)}
      />
      <ProviderKpiCard
        description={snapshotModeDescription(providerStatus)}
        icon={<LockKeyhole aria-hidden="true" />}
        label="Snapshot mode"
        tone={
          providerStatus?.snapshot.locked_provider_data ? "support" : "info"
        }
        value={snapshotModeLabel(providerStatus)}
      />
      <ProviderKpiCard
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
    </section>
  )
}
