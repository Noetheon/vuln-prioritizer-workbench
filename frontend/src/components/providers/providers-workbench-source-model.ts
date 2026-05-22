import type {
  ProviderSourceStatusPublic,
  ProviderStatusPublic,
} from "@/api-client"
import type { VpwBadgeTone } from "@/components/vpw"
import {
  formatCacheAge,
  providerSnapshotSummary,
  providerSourceDetail,
  providerSourceState,
} from "@/lib/provider-format"
import { formatDateTime } from "./providers-workbench-status-model"
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

function normalizedSourceName(value: string) {
  return value.trim().toLowerCase().replaceAll("_", "-")
}

export function sourceDisplayName(sourceName: string) {
  const normalized = normalizedSourceName(sourceName)
  if (normalized.includes("nvd")) {
    return "NVD / CVSS"
  }
  if (normalized.includes("epss") || normalized.includes("first")) {
    return "FIRST EPSS"
  }
  if (normalized.includes("kev") || normalized.includes("cisa")) {
    return "CISA KEV"
  }
  if (normalized.includes("provider-snapshot")) {
    return "Snapshot metadata"
  }
  if (normalized.includes("snapshot")) {
    return "Snapshot metadata"
  }
  return sourceName
}

function sourcePurpose(sourceName: string) {
  const normalized = normalizedSourceName(sourceName)
  if (normalized.includes("nvd")) {
    return "CVSS severity and CVE metadata"
  }
  if (normalized.includes("epss") || normalized.includes("first")) {
    return "Probability signal"
  }
  if (normalized.includes("kev") || normalized.includes("cisa")) {
    return "Known exploited vulnerability signal"
  }
  if (normalized.includes("snapshot")) {
    return "Recorded provider replay evidence"
  }
  return "Supplemental provider signal"
}

function sourceStatus(source: ProviderSourceStatusPublic) {
  const state = providerSourceState(source)
  if (source.last_error && !source.available) {
    return { label: "Unavailable", token: "unavailable" }
  }
  if (state === "available") {
    return source.last_sync || source.value
      ? { label: "Fresh", token: "fresh" }
      : { label: "Available", token: "available" }
  }
  if (state === "stale") {
    return { label: "Stale", token: "stale" }
  }
  return { label: "Missing", token: "missing" }
}

function sourceStatusTone(statusToken: string): VpwBadgeTone {
  switch (statusToken) {
    case "fresh":
    case "available":
      return "success"
    case "stale":
      return "warning"
    case "missing":
    case "unavailable":
      return "critical"
    default:
      return "neutral"
  }
}

function evidenceUse(source: ProviderSourceStatusPublic) {
  return source.selected ? "Included" : "Not included"
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
  return selected.length > 0
    ? selected.map(sourceDisplayName).join(", ")
    : "No sources selected"
}

export function redactedSourcePath(value: string | null | undefined) {
  if (!value) {
    return "Not recorded"
  }
  const parts = value.split("/").filter(Boolean)
  if (parts.length <= 2) {
    return value
  }
  return `.../${parts.slice(-2).join("/")}`
}

export function sourceHashes(providerStatus: ProviderStatusPublic | null) {
  const hashes = providerStatus?.snapshot.source_hashes ?? {}
  const values = Object.entries(hashes).map(([source, hash]) =>
    typeof hash === "string" && hash.trim()
      ? `${sourceDisplayName(source)}: ${hash}`
      : `${sourceDisplayName(source)}: not recorded`,
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
    const status = sourceStatus(source)
    return {
      age: formatCacheAge(source.cache_age_seconds),
      evidenceUse: evidenceUse(source),
      id: source.name,
      lastUpdated: formatDateTime(source.last_sync),
      name: sourceDisplayName(source.name),
      notes: providerSourceDetail(source),
      purpose: sourcePurpose(source.name),
      statusLabel: status.label,
      statusToken: status.token,
      technicalName: source.name,
      tone: sourceStatusTone(status.token),
      value: source.value ?? "Not recorded",
    }
  })

  rows.push({
    age: formatCacheAge(providerStatus.cache_age_seconds),
    evidenceUse: providerStatus.snapshot.selected_sources?.length
      ? "Included"
      : "Recorded",
    id: "provider-snapshot",
    lastUpdated: formatDateTime(
      providerStatus.snapshot.generated_at ??
        providerStatus.snapshot.created_at ??
        providerStatus.last_sync,
    ),
    name: "Provider snapshot",
    notes: providerStatus.snapshot.content_hash
      ? "Snapshot metadata and content hash are recorded."
      : providerSnapshotSummary(providerStatus),
    purpose: "Recorded provider replay evidence",
    statusLabel: providerStatus.snapshot.missing
      ? "Missing"
      : providerStatus.status === "ok"
        ? "Fresh"
        : "Stale",
    statusToken: providerStatus.snapshot.missing
      ? "missing"
      : providerStatus.status === "ok"
        ? "fresh"
        : "stale",
    technicalName: "provider_snapshot",
    tone: providerStatus.snapshot.missing
      ? "critical"
      : providerStatus.status === "ok"
        ? "success"
        : "warning",
    value:
      providerStatus.snapshot.mode ??
      providerStatus.snapshot_mode ??
      "Not recorded",
  })

  return rows
}

export function providerSourceCounts(
  rows: readonly ProviderSourceRow[],
): ProviderSourceCounts {
  return {
    availableSources: rows.filter((row) =>
      ["available", "fresh"].includes(row.statusToken),
    ).length,
    staleSources: rows.filter((row) => row.statusToken === "stale").length,
    missingSources: rows.filter((row) =>
      ["missing", "unavailable"].includes(row.statusToken),
    ).length,
  }
}

export function snapshotSources(rows: readonly ProviderSourceRow[]) {
  return rows.map((row) => ({
    name: row.name,
    status: row.statusLabel,
    tone: row.tone,
  }))
}
