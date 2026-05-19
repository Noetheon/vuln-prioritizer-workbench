import type { ProviderStatusPublic } from "@/api-client"
import type { VpwTimelineItem } from "@/components/vpw/VpwTimeline"

export function providerHealthTone(
  providerStatus: ProviderStatusPublic | null,
) {
  if (providerStatus === null) {
    return "info"
  }
  return providerStatus.status === "ok" ? "success" : "warning"
}

export function evidenceReadinessTone(
  providerStatus: ProviderStatusPublic | null,
) {
  if (providerStatus === null) {
    return "info"
  }
  if (providerStatus.last_error) {
    return "critical"
  }
  return providerStatus.status === "ok" ? "success" : "warning"
}

export function dataQualityLabel(providerStatus: ProviderStatusPublic | null) {
  if (providerStatus === null) {
    return "Checking"
  }
  if (providerStatus.last_error) {
    return "Degraded"
  }
  if ((providerStatus.warnings ?? []).length > 0) {
    return "Warnings"
  }
  if ((providerStatus.sources ?? []).some((source) => !source.available)) {
    return "Gaps"
  }
  return "Usable"
}

export function evidenceReadinessLabel(
  providerStatus: ProviderStatusPublic | null,
) {
  if (providerStatus === null) {
    return "Checking"
  }
  return providerStatus.last_error ? "Needs attention" : "Evidence ready"
}

export function buildProviderEvidenceFlowItems({
  availableSources,
  evidenceReadiness,
  missingSources,
  providerStatus,
}: {
  availableSources: number
  evidenceReadiness: string
  missingSources: number
  providerStatus: ProviderStatusPublic | null
}): readonly VpwTimelineItem[] {
  return [
    {
      description:
        "NVD, EPSS and KEV context is read from the stored source state.",
      meta: `${availableSources} available`,
      title: "Data sources",
      tone: missingSources > 0 ? "warning" : "success",
    },
    {
      description: providerStatus?.snapshot.locked_provider_data
        ? "Locked snapshot mode is active for reproducible evidence."
        : "Stored provider data is available for evidence generation.",
      meta: providerStatus?.snapshot_mode ?? "missing",
      title: "Snapshot mode",
      tone: providerStatus?.status === "ok" ? "success" : "warning",
    },
    {
      description:
        "Provider data is included in evidence bundles and executive reports.",
      meta: evidenceReadiness,
      title: "Evidence connection",
      tone: providerStatus?.last_error ? "critical" : "success",
    },
  ]
}
