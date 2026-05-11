import type { FormEvent } from "react"

import type {
  ApiTokenCreatePublic,
  ApiTokenPublic,
  ProjectPublic,
  ProviderStatusPublic,
  UserPublic,
  WorkbenchStatus,
} from "@/api-client"
import type { VpwBadgeTone } from "@/components/vpw"
import { formatCacheAge, providerSnapshotSummary } from "@/lib/provider-format"
import type { ApiTokenScope } from "./settings-token-model"

export type SettingsWorkbenchProps = {
  activeSettingsTab: SettingsTab
  apiTokenActionLoading: boolean
  apiTokenError: string
  apiTokenMessage: string
  apiTokenName: string
  apiTokenProjectId: string
  apiTokenProjectOptions: readonly ProjectPublic[]
  apiTokenScopeOptions: readonly ApiTokenScope[]
  apiTokenScopes: readonly ApiTokenScope[]
  apiTokens: readonly ApiTokenPublic[]
  apiTokensLoading: boolean
  createdApiToken: ApiTokenCreatePublic | null
  currentUser: UserPublic | null
  providerStatus: ProviderStatusPublic | null
  providerStatusError: string
  providerStatusLoading: boolean
  status: WorkbenchStatus | null
  statusError: string
  onClearCreatedApiToken: () => void
  onApiTokenNameChange: (value: string) => void
  onApiTokenProjectChange: (value: string) => void
  onCreateApiToken: (event: FormEvent<HTMLFormElement>) => void | Promise<void>
  onRevokeApiToken: (token: ApiTokenPublic) => void | Promise<void>
  onSettingsTabChange: (tab: SettingsTab) => void
  onToggleApiTokenScope: (scope: ApiTokenScope) => void
}

export const settingsTabOptions = [
  { label: "Overview", value: "overview" },
  { label: "API Tokens", value: "tokens" },
  { label: "Runtime & Providers", value: "runtime" },
  { label: "Diagnostics", value: "diagnostics" },
] as const

export type SettingsTab = (typeof settingsTabOptions)[number]["value"]

const settingsTabValues = new Set<string>(
  settingsTabOptions.map((option) => option.value),
)

export function normalizeSettingsTab(
  value: string | null | undefined,
): SettingsTab {
  return value && settingsTabValues.has(value)
    ? (value as SettingsTab)
    : "overview"
}

export type ProviderConfigRow = {
  id: string
  setting: string
  value: string
  detail: string
  tone: VpwBadgeTone
}

export function userLabel(user: UserPublic | null) {
  return user?.email ?? "Loading user"
}

function sourceByName(
  providerStatus: ProviderStatusPublic | null,
  sourceName: string,
) {
  return (providerStatus?.sources ?? []).find(
    (source) => source.name.toLowerCase() === sourceName,
  )
}

function sourceAvailability(
  providerStatus: ProviderStatusPublic | null,
  sourceName: string,
) {
  const source = sourceByName(providerStatus, sourceName)
  if (!source) {
    return { label: "Not reported", tone: "neutral" as VpwBadgeTone }
  }
  if (source.stale) {
    return { label: "Stale", tone: "warning" as VpwBadgeTone }
  }
  return source.available
    ? { label: "Available", tone: "success" as VpwBadgeTone }
    : { label: "Missing", tone: "critical" as VpwBadgeTone }
}

export function providerHealth(providerStatus: ProviderStatusPublic | null) {
  if (!providerStatus) {
    return { label: "Loading", tone: "info" as VpwBadgeTone }
  }
  return providerStatus.status === "ok"
    ? { label: "Healthy", tone: "success" as VpwBadgeTone }
    : { label: "Review", tone: "warning" as VpwBadgeTone }
}

export function evidenceReadiness(
  providerStatus: ProviderStatusPublic | null,
  providerStatusError: string,
  statusError: string,
) {
  if (providerStatusError || statusError || providerStatus?.last_error) {
    return { label: "Needs review", tone: "critical" as VpwBadgeTone }
  }
  if (!providerStatus) {
    return { label: "Checking", tone: "info" as VpwBadgeTone }
  }
  return providerStatus.status === "ok"
    ? { label: "Ready", tone: "success" as VpwBadgeTone }
    : { label: "Partial", tone: "warning" as VpwBadgeTone }
}

export function safeDiagnosticsCode({
  providerStatus,
  status,
  statusError,
}: {
  providerStatus: ProviderStatusPublic | null
  status: WorkbenchStatus | null
  statusError: string
}) {
  return JSON.stringify(
    {
      app: status?.app ?? "unavailable",
      backendStatus: status?.status ?? "unavailable",
      corePackage: status?.core_package ?? "unavailable",
      coreVersion: status?.core_version ?? "unavailable",
      databaseStatus: status?.database_status ?? "unavailable",
      schemaStatus: status?.schema_status ?? "unavailable",
      providerStatus: providerStatus?.status ?? "unavailable",
      providerSnapshotMode: providerStatus?.snapshot_mode ?? "unavailable",
      providerSourceCount: providerStatus?.sources?.length ?? 0,
      statusError: statusError || null,
    },
    null,
    2,
  )
}

export function providerConfigRows(
  providerStatus: ProviderStatusPublic | null,
): ProviderConfigRow[] {
  const nvd = sourceAvailability(providerStatus, "nvd")
  const epss = sourceAvailability(providerStatus, "epss")
  const kev = sourceAvailability(providerStatus, "kev")

  return [
    {
      id: "nvd",
      setting: "NVD source",
      value: nvd.label,
      detail:
        "Availability is reported by the backend without exposing provider secrets.",
      tone: nvd.tone,
    },
    {
      id: "epss",
      setting: "EPSS provider",
      value: epss.label,
      detail: "Exploit probability source used for prioritization.",
      tone: epss.tone,
    },
    {
      id: "kev",
      setting: "KEV provider",
      value: kev.label,
      detail: "Known Exploited Vulnerabilities signal used for evidence.",
      tone: kev.tone,
    },
    {
      id: "snapshot-mode",
      setting: "Snapshot mode",
      value: providerStatus?.snapshot_mode ?? "Not reported",
      detail: providerSnapshotSummary(providerStatus),
      tone: providerStatus?.snapshot_mode ? "info" : "neutral",
    },
    {
      id: "cache-age",
      setting: "Cache age",
      value: formatCacheAge(providerStatus?.cache_age_seconds),
      detail: "Provider cache age reported by the Workbench backend.",
      tone: providerStatus?.cache_age_seconds ? "info" : "neutral",
    },
    {
      id: "upload-size",
      setting: "Max upload size",
      value: "Not exposed",
      detail:
        "The current settings API does not publish upload limit metadata.",
      tone: "neutral",
    },
  ]
}
