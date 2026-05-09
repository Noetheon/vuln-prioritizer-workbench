import type {
  ProviderSourceStatusPublic,
  ProviderStatusPublic,
} from "@/api-client"
import type { VpwBadgeTone } from "@/components/vpw"
import type { VpwTimelineItem } from "@/components/vpw/VpwTimeline"
import {
  formatCacheAge,
  providerSnapshotSummary,
  providerSourceDetail,
  providerSourceLabel,
  providerSourceState,
} from "@/lib/provider-format"

export type ProvidersWorkbenchProps = {
  providerStatus: ProviderStatusPublic | null
  providerStatusError: string
  providerStatusLoading: boolean
  onRefreshProviderStatus: () => void
}

export type ProviderSourceRow = {
  cacheAge: string
  detail: string
  id: string
  lastUpdated: string
  name: string
  sourceType: string
  status: string
  tone: VpwBadgeTone
  usedInEvidence: string
  value: string
}

export type ProviderSourceCounts = {
  availableSources: number
  staleSources: number
  missingSources: number
}

const fallbackProviderSources: ProviderSourceStatusPublic[] = [
  { name: "nvd", available: false, value: null },
  { name: "epss", available: false, value: null },
  { name: "kev", available: false, value: null },
]

function objectRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {}
}

function stringValue(value: unknown) {
  return typeof value === "string" && value.trim() ? value : null
}

export function formatDateTime(value: string | null | undefined) {
  if (!value) {
    return "N.A."
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date)
}

function sourceStatusLabel(source: ProviderSourceStatusPublic) {
  const state = providerSourceState(source)
  if (state === "available") {
    return source.last_sync || source.value ? "fresh" : "available"
  }
  return state
}

function sourceStatusTone(status: string): VpwBadgeTone {
  switch (status) {
    case "fresh":
    case "available":
      return "success"
    case "stale":
      return "warning"
    case "missing":
      return "critical"
    default:
      return "neutral"
  }
}

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

function sourceType(sourceName: string) {
  switch (sourceName.toLowerCase()) {
    case "nvd":
      return "Vulnerability database"
    case "epss":
      return "Exploit probability"
    case "kev":
      return "Known exploited"
    case "provider snapshot":
      return "Snapshot metadata"
    case "osv":
      return "Advisory database"
    default:
      return "Provider"
  }
}

export function snapshotId(providerStatus: ProviderStatusPublic | null) {
  const metadata = objectRecord(providerStatus?.snapshot.source_metadata)
  return (
    stringValue(metadata.snapshot_id) ??
    providerStatus?.snapshot.id ??
    "No snapshot ID recorded"
  )
}

export function selectedSources(providerStatus: ProviderStatusPublic | null) {
  const selected = providerStatus?.snapshot.selected_sources ?? []
  return selected.length > 0 ? selected.join(", ") : "No sources selected"
}

export function sourceHashes(providerStatus: ProviderStatusPublic | null) {
  const hashes = providerStatus?.snapshot.source_hashes ?? {}
  const values = Object.entries(hashes).map(([source, hash]) =>
    typeof hash === "string" && hash.trim()
      ? `${source}: ${hash}`
      : `${source}: N.A.`,
  )
  return values.length > 0 ? values.join(" | ") : "No source hashes recorded"
}

export function sourceRows(
  providerStatus: ProviderStatusPublic | null,
): ProviderSourceRow[] {
  const rows = (providerStatus?.sources ?? fallbackProviderSources).map(
    (source) => {
      const status = sourceStatusLabel(source)
      return {
        cacheAge: formatCacheAge(source.cache_age_seconds),
        detail: providerSourceDetail(source),
        id: source.name,
        lastUpdated: formatDateTime(source.last_sync),
        name: providerSourceLabel(source),
        sourceType: sourceType(source.name),
        status,
        tone: sourceStatusTone(status),
        usedInEvidence: source.selected ? "Yes" : "No",
        value: source.value ?? "N.A.",
      }
    },
  )

  rows.push({
    cacheAge: formatCacheAge(providerStatus?.cache_age_seconds),
    detail: providerSnapshotSummary(providerStatus),
    id: "provider-snapshot",
    lastUpdated: formatDateTime(
      providerStatus?.snapshot.generated_at ??
        providerStatus?.snapshot.created_at ??
        providerStatus?.last_sync,
    ),
    name: "PROVIDER SNAPSHOT",
    sourceType: "Snapshot metadata",
    status: providerStatus?.snapshot.missing
      ? "missing"
      : providerStatus?.status === "ok"
        ? "fresh"
        : "stale",
    tone: providerStatus?.snapshot.missing
      ? "critical"
      : providerStatus?.status === "ok"
        ? "success"
        : "warning",
    usedInEvidence: providerStatus?.snapshot.selected_sources?.length
      ? "Yes"
      : "Recorded",
    value:
      providerStatus?.snapshot.mode ?? providerStatus?.snapshot_mode ?? "N.A.",
  })

  return rows
}

export function providerSourceCounts(
  rows: readonly ProviderSourceRow[],
): ProviderSourceCounts {
  return {
    availableSources: rows.filter((row) =>
      ["available", "fresh"].includes(row.status),
    ).length,
    staleSources: rows.filter((row) => row.status === "stale").length,
    missingSources: rows.filter((row) => row.status === "missing").length,
  }
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

export function snapshotSources(rows: readonly ProviderSourceRow[]) {
  return rows.map((row) => ({
    name: row.name,
    status: row.status,
    tone: row.tone,
  }))
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
      title: "Provider sources",
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
