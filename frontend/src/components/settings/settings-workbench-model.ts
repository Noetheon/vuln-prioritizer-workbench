import type {
  ProviderStatusPublic,
  UploadPolicyPublic,
  WorkbenchStatus,
} from "@/api-client"
import type { VpwBadgeTone } from "@/components/vpw"
import { formatCacheAge, providerSnapshotSummary } from "@/lib/provider-format"
import { FRONTEND_VERSION } from "@/lib/runtime-config"
import { formatDateTime as formatWorkbenchDateTime } from "../../lib/date-format.ts"

export type SettingsWorkbenchProps = {
  activeSettingsTab: SettingsTab
  providerStatus: ProviderStatusPublic | null
  providerStatusError: string
  providerStatusLoading: boolean
  uploadPolicy: UploadPolicyPublic | null
  capabilitiesError: string
  selectedProjectId: string
  status: WorkbenchStatus | null
  statusError: string
  onSettingsTabChange: (tab: SettingsTab) => void
}

export const settingsTabOptions = [
  { label: "Overview", value: "overview" },
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

export function formatDateTime(value: string | null | undefined) {
  return formatWorkbenchDateTime(value, {
    invalidFallback: (invalidValue) => invalidValue,
  })
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

export function workerHealth(status: WorkbenchStatus | null) {
  const workerStatus = status?.worker_status
  if (!workerStatus) {
    return { label: "Checking", tone: "info" as VpwBadgeTone }
  }
  if (workerStatus === "ready") {
    return { label: "Ready", tone: "success" as VpwBadgeTone }
  }
  if (workerStatus === "unknown") {
    return { label: "Unknown", tone: "warning" as VpwBadgeTone }
  }
  return { label: "Not ready", tone: "warning" as VpwBadgeTone }
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
      schemaVersion: status?.schema_version ?? "unavailable",
      environment: status?.environment ?? "unavailable",
      runtimeMode: status?.runtime_mode ?? "unavailable",
      frontendVersion: FRONTEND_VERSION,
      backendStatus: status?.status ?? "unavailable",
      corePackage: status?.core_package ?? "unavailable",
      coreVersion: status?.core_version ?? "unavailable",
      databaseStatus: status?.database_status ?? "unavailable",
      schemaStatus: status?.schema_status ?? "unavailable",
      alembicHead: status?.alembic_head ?? "unavailable",
      demoWorkspaceEnabled: status?.demo_workspace_enabled ?? false,
      workerStatus: status?.worker_status ?? "unavailable",
      workerLastSeenAt: status?.worker_last_seen_at ?? null,
      apiDocsEnabled: status?.api_docs_enabled ?? false,
      apiDocsPath: status?.api_docs_path ?? null,
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
  uploadPolicy: UploadPolicyPublic | null,
  capabilitiesError = "",
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
      detail: "EPSS probability source used for prioritization.",
      tone: epss.tone,
    },
    {
      id: "kev",
      setting: "KEV provider",
      value: kev.label,
      detail: "CISA KEV signal used for evidence.",
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
      value: uploadPolicy
        ? formatByteLimit(uploadPolicy.max_upload_bytes)
        : "Unavailable",
      detail: capabilitiesError || "Maximum accepted aggregate import upload size.",
      tone: uploadPolicy ? "info" : "warning",
    },
    {
      id: "request-body-size",
      setting: "Max request body size",
      value: uploadPolicy
        ? formatByteLimit(uploadPolicy.max_request_body_bytes)
        : "Unavailable",
      detail: capabilitiesError || "Maximum accepted non-upload API request body size.",
      tone: uploadPolicy ? "info" : "warning",
    },
  ]
}

export function formatByteLimit(value: number) {
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`
  return `${(value / (1024 * 1024)).toFixed(1)} MB`
}
