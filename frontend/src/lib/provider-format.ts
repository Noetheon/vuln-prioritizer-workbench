import type {
  ProviderSourceStatusPublic,
  ProviderStatusPublic,
  WorkbenchStatus,
} from "../api-client"

export type ProviderFreshnessTone = "run" | "kev" | "high"
export type ProviderSourceState = "available" | "stale" | "missing"

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
    return "N.A."
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

export function formatProviderFreshness(
  providerStatus: ProviderStatusPublic | null,
): ProviderFreshnessSummary {
  if (providerStatus === null) {
    return {
      detail: "provider status loading",
      tone: "run",
      value: "Loading",
    }
  }
  if (providerStatus.status === "ok") {
    return {
      detail:
        providerStatus.cache_age_seconds !== null &&
        providerStatus.cache_age_seconds !== undefined
          ? `${formatCacheAge(providerStatus.cache_age_seconds)} old`
          : providerStatus.snapshot_mode,
      tone: "kev",
      value: "Fresh",
    }
  }
  return {
    detail:
      providerStatus.last_error ??
      providerStatus.warnings?.[0] ??
      "No snapshot recorded",
    tone: "high",
    value: "Needs sync",
  }
}

export function providerSnapshotHealth(
  providerStatus: ProviderStatusPublic | null,
) {
  if (providerStatus === null) {
    return "Checking"
  }
  return providerStatus.status === "ok" ? "Fresh" : "Needs sync"
}

export function providerSnapshotSummary(
  providerStatus: ProviderStatusPublic | null,
) {
  if (providerStatus === null) {
    return "Provider snapshot loading"
  }
  return providerStatus.status === "ok"
    ? "Provider snapshot available"
    : "Provider snapshot needs attention"
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
    "Status is based on the latest stored provider snapshot.",
    "Missing, stale, or failed provider evidence is shown as degraded data quality.",
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
      label: "Provider snapshot",
      value: providerSnapshotHealth(providerStatus),
    },
    {
      label: "Evidence",
      value: evidenceReadiness(providerStatus),
    },
  ]
}
