import {
  Database,
  FileArchive,
  FileCheck2,
  LockKeyhole,
  Signal,
} from "lucide-react"
import type { ReactNode } from "react"

import type { ProviderStatusPublic } from "@/api-client"
import {
  VpwCompactMetric,
  VpwMetricStrip,
  type VpwCompactTone,
} from "@/components/vpw"
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
  tone: VpwCompactTone
  value: string
}) {
  return (
    <VpwCompactMetric
      description={<span title={description}>{description}</span>}
      icon={icon}
      label={label}
      tone={tone}
      value={value}
    />
  )
}

export function ProviderMetricsGrid({
  providerStatus,
}: ProviderMetricsGridProps) {
  return (
    <VpwMetricStrip
      aria-label="Provider summary"
      className="providers-kpi-strip"
      minCardWidth="13rem"
    >
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
    </VpwMetricStrip>
  )
}
