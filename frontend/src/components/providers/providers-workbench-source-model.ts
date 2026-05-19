import type {
  ProviderSourceStatusPublic,
  ProviderStatusPublic,
} from "@/api-client"
import type { VpwBadgeTone } from "@/components/vpw"
import {
  formatCacheAge,
  providerSnapshotSummary,
  providerSourceDetail,
  providerSourceLabel,
  providerSourceState,
} from "@/lib/provider-format"
import type {
  ProviderSourceCounts,
  ProviderSourceRow,
} from "./providers-workbench-types"

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
    return "Not recorded"
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
      : `${source}: not recorded`,
  )
  return values.length > 0 ? values.join(" | ") : "No source hashes recorded"
}

export function sourceRows(
  providerStatus: ProviderStatusPublic | null,
): ProviderSourceRow[] {
  if (!providerStatus) {
    return []
  }

  const rows = (providerStatus.sources ?? []).map((source) => {
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
      value: source.value ?? "Not recorded",
    }
  })

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
      providerStatus?.snapshot.mode ??
      providerStatus?.snapshot_mode ??
      "Not recorded",
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

export function snapshotSources(rows: readonly ProviderSourceRow[]) {
  return rows.map((row) => ({
    name: row.name,
    status: row.status,
    tone: row.tone,
  }))
}
