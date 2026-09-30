import type {
  ProviderReachabilityPublic,
  ProviderSourceReachabilityPublic,
  ProviderSourceStatusPublic,
  ProviderStatusPublic,
  WorkbenchStatus,
} from "../api-client"

export type ProviderFreshnessTone = "run" | "kev" | "high"
export type ProviderSourceState = "available" | "stale" | "missing"
export type ProviderDataState =
  | "checking"
  | "fresh"
  | "stale"
  | "not_loaded"
  | "degraded"

const providerDataStateLabels: Record<ProviderDataState, string> = {
  checking: "Checking",
  degraded: "Needs attention",
  fresh: "Fresh",
  not_loaded: "Not fetched yet",
  stale: "Stale",
}

export type ProviderFreshnessSummary = {
  detail: string
  tone: ProviderFreshnessTone
  value: string
}

export type DataServicesSummaryItem = {
  label: string
  value: string
}

export function formatCacheAge(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) {
    return "No cache age"
  }
  if (seconds < 60) {
    return `${seconds}s`
  }
  if (seconds < 3600) {
    return `${Math.floor(seconds / 60)}m`
  }
  if (seconds < 86400) {
    return `${Math.floor(seconds / 3600)}h`
  }
  return `${Math.floor(seconds / 86400)}d`
}

/**
 * Classify provider data the way the backend does: fresh, stale (older than the
 * configured threshold), not fetched yet (a new install), or degraded (errors).
 */
export function providerDataState(
  providerStatus: ProviderStatusPublic | null,
): ProviderDataState {
  if (providerStatus === null) {
    return "checking"
  }
  if (providerStatus.last_error || providerStatus.status === "degraded") {
    return "degraded"
  }
  switch (providerStatus.status) {
    case "ok":
      return "fresh"
    case "stale":
      return "stale"
    case "not_loaded":
      return "not_loaded"
    default:
      return "degraded"
  }
}

export function providerDataStateLabel(
  providerStatus: ProviderStatusPublic | null,
) {
  return providerDataStateLabels[providerDataState(providerStatus)]
}

export function providerDataTone(
  providerStatus: ProviderStatusPublic | null,
): "success" | "warning" | "info" {
  switch (providerDataState(providerStatus)) {
    case "fresh":
      return "success"
    case "stale":
    case "degraded":
      return "warning"
    default:
      return "info"
  }
}

export function providerStaleAfterLabel(
  providerStatus: ProviderStatusPublic | null,
) {
  const hours = providerStatus?.stale_after_hours
  if (hours === null || hours === undefined) {
    return "Stale threshold not reported"
  }
  return `Stale after ${hours} hour${hours === 1 ? "" : "s"}`
}

export function formatProviderFreshness(
  providerStatus: ProviderStatusPublic | null,
): ProviderFreshnessSummary {
  const state = providerDataState(providerStatus)
  const age = providerStatus?.cache_age_seconds
  const ageLabel =
    age === null || age === undefined ? null : `${formatCacheAge(age)} old`
  switch (state) {
    case "checking":
      return {
        detail: "provider status loading",
        tone: "run",
        value: "Loading",
      }
    case "fresh":
      return {
        detail: ageLabel ?? providerStatus?.snapshot_mode ?? "",
        tone: "kev",
        value: providerDataStateLabels.fresh,
      }
    case "stale":
      return {
        detail: ageLabel
          ? `${ageLabel}; ${providerStaleAfterLabel(providerStatus).toLowerCase()}`
          : (providerStatus?.warnings?.[0] ?? "Provider data is stale"),
        tone: "high",
        value: providerDataStateLabels.stale,
      }
    case "not_loaded":
      return {
        detail: "The first import fetches NVD, EPSS, and KEV",
        tone: "run",
        value: providerDataStateLabels.not_loaded,
      }
    default:
      return {
        detail:
          providerStatus?.last_error ??
          providerStatus?.warnings?.[0] ??
          "Provider data needs attention",
        tone: "high",
        value: providerDataStateLabels.degraded,
      }
  }
}

export type ImportProviderReadiness = {
  label: string
  message: string
  status: "passed" | "warning"
}

// What an import loses when a live feed does not answer.
const unreachableConsequences: Record<string, string> = {
  epss: "priorities will be computed without EPSS",
  kev: "KEV status will come from the cached catalog, or stay unknown without one",
  nvd: "CVSS scores and descriptions will be missing",
}

/**
 * What provider data an import will use: a snapshot the user picked, the
 * runtime's default snapshot (demo runtimes), or live NVD, EPSS, and KEV.
 * A live import warns first when a feed does not answer from this Workbench.
 */
export function importProviderReadiness(
  providerStatus: ProviderStatusPublic | null,
  providerSnapshotFile?: string | null,
  reachability?: ProviderReachabilityPublic | null,
): ImportProviderReadiness {
  if (providerSnapshotFile) {
    return {
      label: providerSnapshotFile,
      message: "The selected provider snapshot is replayed for this import.",
      status: "passed",
    }
  }
  if (providerStatus === null) {
    return {
      label: "Checking provider data",
      message: "Provider status is still loading.",
      status: "warning",
    }
  }
  if (providerStatus.import_provider_mode === "default_snapshot") {
    if (providerStatus.snapshot.missing) {
      return {
        label: "Default provider snapshot",
        message: "No default provider snapshot is recorded for this runtime.",
        status: "warning",
      }
    }
    return providerDataState(providerStatus) === "fresh"
      ? {
          label: "Default provider snapshot",
          message: "The runtime's default provider snapshot is replayed for this import.",
          status: "passed",
        }
      : {
          label: "Default provider snapshot",
          message: `The runtime's default provider snapshot is replayed for this import. ${providerStatus.warnings?.[0] ?? "Its data is stale."}`,
          status: "warning",
        }
  }
  const unreachable =
    reachability?.sources.filter((source) => !source.reachable) ?? []
  if (unreachable.length > 0) {
    return {
      label: "Live provider data",
      message: unreachableProvidersMessage(unreachable),
      status: "warning",
    }
  }
  if (providerStatus.last_error) {
    return {
      label: "Live provider data",
      message: `NVD, EPSS, and KEV are fetched live during the import. The last provider update failed: ${providerStatus.last_error}`,
      status: "warning",
    }
  }
  return {
    label: "Live provider data",
    message: "NVD, EPSS, and KEV are fetched live during the import and cached.",
    status: "passed",
  }
}

/** Which feeds do not answer, and what the import loses without them. */
export function unreachableProvidersMessage(
  sources: readonly ProviderSourceReachabilityPublic[],
) {
  const names = listPhrase(
    sources.map((source) =>
      source.detail ? `${source.label} (${source.detail})` : source.label,
    ),
  )
  const consequences = listPhrase(
    sources.map(
      (source) =>
        unreachableConsequences[source.source] ??
        `${source.label} data will be missing`,
    ),
  )
  const verb = sources.length === 1 ? "does" : "do"
  return `${names} ${verb} not answer from this Workbench. The import still runs, but ${consequences}. To import without live data, enter a provider snapshot under Add context.`
}

function listPhrase(items: readonly string[]) {
  if (items.length <= 2) return items.join(" and ")
  return `${items.slice(0, -1).join(", ")}, and ${items[items.length - 1]}`
}

export function providerSnapshotHealth(
  providerStatus: ProviderStatusPublic | null,
) {
  return providerDataStateLabel(providerStatus)
}

export function providerSnapshotSummary(
  providerStatus: ProviderStatusPublic | null,
) {
  switch (providerDataState(providerStatus)) {
    case "checking":
      return "Provider data loading"
    case "fresh":
      return "Provider data is fresh"
    case "stale":
      return "Provider data is stale"
    case "not_loaded":
      return "Provider data not fetched yet"
    default:
      return "Provider data needs attention"
  }
}

function snapshotMode(providerStatus: ProviderStatusPublic) {
  return `${providerStatus.snapshot.mode ?? providerStatus.snapshot_mode}`.toLowerCase()
}

export function snapshotModeLabel(
  providerStatus: ProviderStatusPublic | null,
) {
  if (providerStatus === null) {
    return "Checking"
  }
  if (providerStatus.snapshot_mode === "live") {
    return "Live provider data"
  }
  if (providerStatus.snapshot.locked_provider_data) {
    return "Locked snapshot"
  }
  const mode = snapshotMode(providerStatus)
  if (mode === "demo") {
    return "Demo snapshot"
  }
  if (mode.includes("replay")) {
    return "Replay snapshot"
  }
  if (mode === "missing") {
    return "No snapshot"
  }
  return "Stored snapshot"
}

export function snapshotModeDescription(
  providerStatus: ProviderStatusPublic | null,
) {
  if (providerStatus === null) {
    return "Snapshot status is still loading."
  }
  if (providerStatus.snapshot_mode === "live") {
    return "Imports fetch NVD, EPSS, and KEV live and keep them in the local provider cache."
  }
  if (providerStatus.snapshot.locked_provider_data) {
    return "Provider replay is deterministic for evidence review."
  }
  const mode = snapshotMode(providerStatus)
  if (mode === "demo") {
    return "The demo workspace replays a packaged provider snapshot. Its data is as old as the snapshot."
  }
  if (mode.includes("replay")) {
    return "Recorded snapshot replay is used for reproducibility review."
  }
  return "The latest stored provider snapshot is used for status review."
}

export function providerSourceLabel(source: ProviderSourceStatusPublic) {
  return source.name.toUpperCase()
}

export function providerSourceState(
  source: ProviderSourceStatusPublic,
): ProviderSourceState {
  if (source.stale) {
    return "stale"
  }
  return source.available ? "available" : "missing"
}

export function providerSourceDetail(source: ProviderSourceStatusPublic) {
  if (source.last_error) {
    return source.last_error
  }
  return source.detail ?? "No provider detail recorded."
}

export function providerDataQualityNotes(
  providerStatus: ProviderStatusPublic | null,
) {
  const notes = [
    providerStatus?.snapshot_mode === "live"
      ? "Status is based on when NVD, EPSS, and KEV data was last fetched."
      : "Status is based on when the provider data in the latest snapshot was fetched, not when the snapshot was stored.",
    `${providerStaleAfterLabel(providerStatus)}. Missing, stale, or failed provider evidence is shown as degraded data quality.`,
  ]
  if (providerStatus?.snapshot.locked_provider_data) {
    notes.push(
      "Locked replay is active; live provider lookups are not used for this snapshot.",
    )
  }
  return notes
}

export function workspaceHealthLabel(
  status: WorkbenchStatus | null,
  statusError: string,
) {
  if (status?.status === "ready") {
    return "Data services healthy"
  }
  return statusError || "Data services unavailable"
}

export function workbenchApiHealth(status: WorkbenchStatus | null) {
  if (status === null) {
    return "Checking"
  }
  return status.status === "ready" ? "Ready" : "Unavailable"
}

export function evidenceReadiness(
  providerStatus: ProviderStatusPublic | null,
) {
  if (providerStatus === null) {
    return "Checking"
  }
  return providerStatus.last_error ? "Needs attention" : "Evidence ready"
}

export function dataServicesSummary(
  status: WorkbenchStatus | null,
  providerStatus: ProviderStatusPublic | null,
): DataServicesSummaryItem[] {
  return [
    {
      label: "Data services",
      value: status?.status === "ready" ? "Healthy" : "Unavailable",
    },
    {
      label: "Workbench API",
      value: workbenchApiHealth(status),
    },
    {
      label: "Provider data",
      value: providerSnapshotHealth(providerStatus),
    },
    {
      label: "Evidence",
      value: evidenceReadiness(providerStatus),
    },
  ]
}
