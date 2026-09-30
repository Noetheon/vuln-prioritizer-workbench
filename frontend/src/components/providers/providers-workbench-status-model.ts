import type { ProviderStatusPublic } from "@/api-client"
import type { VpwCompactTone } from "@/components/vpw"
import type { VpwTimelineItem } from "@/components/vpw/VpwTimeline"
import { formatDateTime as formatWorkbenchDateTime } from "../../lib/date-format.ts"
import {
  providerDataState,
  providerDataStateLabel,
  providerDataTone,
  providerStaleAfterLabel,
  snapshotModeDescription,
  snapshotModeLabel,
} from "../../lib/provider-format.ts"

export { snapshotModeDescription, snapshotModeLabel }

export function providerHealthTone(
  providerStatus: ProviderStatusPublic | null,
): VpwCompactTone {
  return providerDataTone(providerStatus)
}

export function providerHealthLabel(
  providerStatus: ProviderStatusPublic | null,
) {
  switch (providerDataState(providerStatus)) {
    case "checking":
      return "Checking"
    case "fresh":
      return "Healthy"
    case "stale":
      return "Stale"
    case "not_loaded":
      return "Not fetched yet"
    default:
      return "Degraded"
  }
}

export function providerHealthDescription(
  providerStatus: ProviderStatusPublic | null,
) {
  switch (providerDataState(providerStatus)) {
    case "checking":
      return "Provider status is still loading."
    case "fresh":
      return "Provider signals are current and available for prioritization."
    case "stale":
      return "Provider data is older than the freshness threshold. Import again or run a provider update."
    case "not_loaded":
      return "No provider data has been fetched yet. The first import fetches NVD, EPSS, and KEV."
    default:
      return "Provider status has a recorded error or missing data."
  }
}

/** Live imports need no snapshot; a missing one only matters for snapshot runtimes. */
function missingRequiredSnapshot(providerStatus: ProviderStatusPublic) {
  return (
    Boolean(providerStatus.snapshot.missing) &&
    providerStatus.snapshot_mode !== "live"
  )
}

function notFetchedYet(providerStatus: ProviderStatusPublic) {
  return providerDataState(providerStatus) === "not_loaded"
}

export function evidenceReadinessTone(
  providerStatus: ProviderStatusPublic | null,
) {
  if (providerStatus === null || notFetchedYet(providerStatus)) {
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
  if (providerStatus === null || notFetchedYet(providerStatus)) {
    return "info"
  }
  if (providerStatus.last_error || missingRequiredSnapshot(providerStatus)) {
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
  if (notFetchedYet(providerStatus)) {
    return "No data yet"
  }
  if (providerStatus.last_error || missingRequiredSnapshot(providerStatus)) {
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
  if (providerStatus === null || notFetchedYet(providerStatus)) {
    return 20
  }
  if (providerStatus.last_error || missingRequiredSnapshot(providerStatus)) {
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
  if (notFetchedYet(providerStatus)) {
    return "Nothing to check yet. The first import fetches NVD, EPSS, and KEV, and reports then carry that provider evidence."
  }
  if (providerStatus.last_error) {
    return "Provider snapshot metadata is present, but the recorded last-error state makes provider evidence incomplete."
  }
  if (missingRequiredSnapshot(providerStatus)) {
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
  return providerDataStateLabel(providerStatus)
}

export function providerFreshnessTone(
  providerStatus: ProviderStatusPublic | null,
): VpwCompactTone {
  return providerDataTone(providerStatus)
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
  return `Data fetched ${formatDateTime(providerStatus?.last_sync)} · Age: ${providerAgeLabel(providerStatus)} · ${providerStaleAfterLabel(providerStatus)}`
}

export function providerFreshnessThresholdLabel(
  providerStatus: ProviderStatusPublic | null,
) {
  return providerStaleAfterLabel(providerStatus)
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
        : snapshotModeDescription(providerStatus),
      meta: snapshotModeLabel(providerStatus),
      title: "Snapshot mode",
      tone: providerDataState(providerStatus) === "fresh" ? "success" : "warning",
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
