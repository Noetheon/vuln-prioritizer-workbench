import type { ProviderStatusPublic } from "@/api-client"
import type { VpwCompactTone } from "@/components/vpw"
import type { VpwTimelineItem } from "@/components/vpw/VpwTimeline"
import { formatDateTime as formatWorkbenchDateTime } from "../../lib/date-format.ts"

const freshnessThresholdDays = 7
const reviewDueThresholdDays = 14

function cacheAgeDays(providerStatus: ProviderStatusPublic | null) {
  const seconds = providerStatus?.cache_age_seconds
  return seconds === null || seconds === undefined
    ? null
    : Math.floor(seconds / 86400)
}

export function providerHealthTone(
  providerStatus: ProviderStatusPublic | null,
): VpwCompactTone {
  if (providerStatus === null) {
    return "info"
  }
  if (providerStatus.last_error || providerStatus.status === "degraded") {
    return "warning"
  }
  return providerStatus.status === "ok" ? "success" : "critical"
}

export function providerHealthLabel(
  providerStatus: ProviderStatusPublic | null,
) {
  if (providerStatus === null) {
    return "Checking"
  }
  if (providerStatus.last_error || providerStatus.status === "degraded") {
    return "Degraded"
  }
  if (providerStatus.status === "ok") {
    return "Healthy"
  }
  return "Unavailable"
}

export function providerHealthDescription(
  providerStatus: ProviderStatusPublic | null,
) {
  if (providerStatus === null) {
    return "Provider status is still loading."
  }
  if (providerStatus.last_error) {
    return "Provider status has a recorded last-error state."
  }
  if (providerStatus.status === "ok") {
    return "Provider signals are available for prioritization."
  }
  return "Provider data is present but needs operational review."
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

export function evidenceReadinessCardTone(
  providerStatus: ProviderStatusPublic | null,
): VpwCompactTone {
  if (providerStatus === null) {
    return "info"
  }
  if (providerStatus.last_error || providerStatus.snapshot.missing) {
    return "warning"
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
  if (providerStatus.last_error || providerStatus.snapshot.missing) {
    return "Incomplete"
  }
  return providerStatus.status === "ok" ? "Ready" : "Incomplete"
}

export function evidenceReadinessFullLabel(
  providerStatus: ProviderStatusPublic | null,
) {
  const label = evidenceReadinessLabel(providerStatus)
  if (label === "Ready") {
    return "Evidence ready"
  }
  if (label === "Incomplete") {
    return "Evidence incomplete"
  }
  return label
}

export function evidenceReadinessScore(
  providerStatus: ProviderStatusPublic | null,
) {
  if (providerStatus === null) {
    return 20
  }
  if (providerStatus.last_error || providerStatus.snapshot.missing) {
    return 35
  }
  if ((providerStatus.warnings ?? []).length > 0) {
    return 72
  }
  const sources = providerStatus.sources ?? []
  if (sources.some((source) => source.stale || !source.available)) {
    return 86
  }
  return 96
}

export function evidenceReadinessExplanation(
  providerStatus: ProviderStatusPublic | null,
) {
  if (providerStatus === null) {
    return "Provider status is still loading, so evidence readiness cannot be finalized yet."
  }
  if (providerStatus.last_error) {
    return "Provider snapshot metadata is present, but the recorded last-error state makes provider evidence incomplete."
  }
  if (providerStatus.snapshot.missing) {
    return "No provider snapshot is recorded, so provider metadata cannot be attached as reproducible evidence."
  }
  if ((providerStatus.warnings ?? []).length > 0) {
    return "Provider snapshot is available and cache metadata is readable, but warnings should be reviewed before reporting."
  }
  if (
    (providerStatus.sources ?? []).some(
      (source) => source.stale || !source.available,
    )
  ) {
    return "Provider snapshot is available, cache is readable, and no last-error state is recorded. Some source timestamps are stale or missing."
  }
  return "Provider snapshot is available, cache is readable, and no last-error state is recorded."
}

export function warningSummary(providerStatus: ProviderStatusPublic | null) {
  if (providerStatus === null) {
    return "Checking"
  }
  if (providerStatus.last_error) {
    return "Errors"
  }
  const warningCount = providerStatus.warnings?.length ?? 0
  if (warningCount > 0) {
    return `${warningCount} warning${warningCount === 1 ? "" : "s"}`
  }
  return "None"
}

export function warningStatusLabel(
  providerStatus: ProviderStatusPublic | null,
) {
  if (providerStatus === null) {
    return "Checking"
  }
  if (providerStatus.last_error) {
    return "Errors"
  }
  return (providerStatus.warnings?.length ?? 0) > 0
    ? "Warnings"
    : "No warnings"
}

export function providerFreshnessLabel(
  providerStatus: ProviderStatusPublic | null,
) {
  if (providerStatus === null) {
    return "Checking"
  }
  const days = cacheAgeDays(providerStatus)
  if (days === null) {
    return "Review due"
  }
  if (days <= freshnessThresholdDays) {
    return "Fresh"
  }
  return days <= reviewDueThresholdDays ? "Review due" : "Stale"
}

export function providerFreshnessTone(
  providerStatus: ProviderStatusPublic | null,
): VpwCompactTone {
  switch (providerFreshnessLabel(providerStatus)) {
    case "Fresh":
      return "success"
    case "Stale":
      return "warning"
    default:
      return "info"
  }
}

export function providerAgeLabel(providerStatus: ProviderStatusPublic | null) {
  const seconds = providerStatus?.cache_age_seconds
  if (seconds === null || seconds === undefined) {
    return "Not recorded"
  }
  if (seconds < 60) {
    return `${seconds} seconds`
  }
  if (seconds < 3600) {
    return `${Math.floor(seconds / 60)} minutes`
  }
  if (seconds < 86400) {
    return `${Math.floor(seconds / 3600)} hours`
  }
  const days = Math.floor(seconds / 86400)
  return `${days} day${days === 1 ? "" : "s"}`
}

export function providerFreshnessDetail(
  providerStatus: ProviderStatusPublic | null,
) {
  return `Last sync ${formatDateTime(providerStatus?.last_sync)} · Age: ${providerAgeLabel(providerStatus)} · Threshold: Fresh <= ${freshnessThresholdDays} days`
}

export function providerFreshnessThresholdLabel() {
  return `Fresh <= ${freshnessThresholdDays} days`
}

export function snapshotModeLabel(
  providerStatus: ProviderStatusPublic | null,
) {
  if (providerStatus === null) {
    return "Checking"
  }
  if (providerStatus.snapshot.locked_provider_data) {
    return "Locked"
  }
  const mode = `${providerStatus.snapshot.mode ?? providerStatus.snapshot_mode}`.toLowerCase()
  if (mode.includes("replay")) {
    return "Replay snapshot"
  }
  return "Live cache"
}

export function snapshotModeDescription(
  providerStatus: ProviderStatusPublic | null,
) {
  if (providerStatus === null) {
    return "Snapshot status is still loading."
  }
  if (providerStatus.snapshot.locked_provider_data) {
    return "Provider replay is deterministic for evidence review."
  }
  const mode = `${providerStatus.snapshot.mode ?? providerStatus.snapshot_mode}`.toLowerCase()
  if (mode.includes("replay")) {
    return "Recorded snapshot replay is used for reproducibility review."
  }
  return "Stored provider cache is used for status review."
}

export function snapshotVerificationLabel(
  providerStatus: ProviderStatusPublic | null,
) {
  return providerStatus?.snapshot.content_hash ? "Verified" : "Not recorded"
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
      description: "NVD, EPSS, and KEV are read from stored provider state.",
      meta: `${availableSources} available`,
      title: "Provider sources",
      tone: missingSources > 0 ? "warning" : "success",
    },
    {
      description: providerStatus?.snapshot.locked_provider_data
        ? "Locked snapshot mode is active for reproducible evidence."
        : "Stored provider cache is used for the current status response.",
      meta: snapshotModeLabel(providerStatus),
      title: "Snapshot mode",
      tone: providerStatus?.status === "ok" ? "success" : "warning",
    },
    {
      description:
        "Findings use transparent CVSS, EPSS, KEV, asset, VEX, waiver, and reviewed ATT&CK context.",
      meta: "Transparent inputs",
      title: "Prioritization",
      tone: providerStatus?.last_error ? "warning" : "success",
    },
    {
      description:
        "Provider metadata is included in evidence bundles and executive reports where available.",
      meta: evidenceReadiness,
      title: "Evidence connection",
      tone: providerStatus?.last_error ? "critical" : "success",
    },
  ]
}

export function formatDateTime(value: string | null | undefined) {
  return formatWorkbenchDateTime(value, {
    invalidFallback: (invalidValue) => invalidValue,
  })
}
