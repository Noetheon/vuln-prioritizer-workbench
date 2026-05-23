import {
  VpwBadge,
  VpwDataTable,
  VpwSkeletonStack,
  VpwStatusBanner,
  VpwTableCard,
  type VpwBadgeTone,
  type VpwDataTableColumn,
} from "@/components/vpw"
import { formatCacheAge, providerSnapshotSummary } from "@/lib/provider-format"
import {
  evidenceReadiness,
  formatDateTime,
  providerHealth,
  type SettingsWorkbenchProps,
} from "./settings-workbench-model"

type SettingsWorkspaceHealthProps = Pick<
  SettingsWorkbenchProps,
  | "providerStatus"
  | "providerStatusError"
  | "providerStatusLoading"
  | "status"
  | "statusError"
>

type SettingsStateRow = {
  id: string
  label: string
  description: string
  state: string
  detail: string
  signal: string
  tone: VpwBadgeTone
}

const settingsStateColumns: readonly VpwDataTableColumn<SettingsStateRow>[] = [
  {
    cell: (row) => (
      <div className="flex min-w-0 flex-col gap-1">
        <span className="font-semibold text-sm text-[var(--vpw-text-primary)]">
          {row.label}
        </span>
        <span className="text-xs text-[var(--vpw-text-muted)]">
          {row.description}
        </span>
      </div>
    ),
    header: "Setting",
    id: "setting",
    width: "25%",
  },
  {
    cell: (row) => <VpwBadge tone={row.tone}>{row.state}</VpwBadge>,
    header: "State",
    id: "state",
    width: "16%",
  },
  {
    cell: (row) => row.detail,
    header: "Detail",
    id: "detail",
  },
  {
    cell: (row) => (
      <span className="font-mono text-xs text-[var(--vpw-text-primary)]">
        {row.signal}
      </span>
    ),
    header: "Signal",
    id: "signal",
    width: "24%",
  },
]

export function SettingsWorkspaceHealth({
  providerStatus,
  providerStatusError,
  providerStatusLoading,
  status,
  statusError,
}: SettingsWorkspaceHealthProps) {
  const errorMessage =
    providerStatus?.last_error || providerStatusError || statusError
  const rows = settingsStateRows({
    providerStatus,
    providerStatusError,
    status,
    statusError,
  })

  return (
    <VpwTableCard
      description="Operational settings expressed as rows, so runtime facts, provider readiness, and support diagnostics scan like one console."
      eyebrow="Console"
      title="Workspace state"
    >
      {providerStatusLoading ? (
        <VpwSkeletonStack rows={5} />
      ) : (
        <VpwDataTable
          caption="Workspace state"
          columns={settingsStateColumns}
          data={rows}
          density="comfortable"
          getRowKey={(row) => row.id}
          minWidth="820px"
        />
      )}

      {errorMessage ? (
        <div className="mt-5">
          <VpwStatusBanner title="Settings need review" tone="critical">
            {errorMessage}
          </VpwStatusBanner>
        </div>
      ) : null}
    </VpwTableCard>
  )
}

function settingsStateRows({
  providerStatus,
  providerStatusError,
  status,
  statusError,
}: Pick<
  SettingsWorkbenchProps,
  "providerStatus" | "providerStatusError" | "status" | "statusError"
>): SettingsStateRow[] {
  const provider = providerHealth(providerStatus)
  const evidence = evidenceReadiness(
    providerStatus,
    providerStatusError,
    statusError,
  )
  const backend = backendState(status?.status, statusError)
  const latestError =
    providerStatus?.last_error || providerStatusError || statusError || "None"

  return [
    {
      description: "Local operator scope",
      detail: "This browser is connected directly to the local Workbench.",
      id: "workspace-profile",
      label: "Workspace profile",
      signal: "No remote tenancy configured",
      state: "Local workspace",
      tone: "success",
    },
    {
      description: "Operator mode",
      detail: "The local operator can manage imports, evidence, and settings.",
      id: "access-model",
      label: "Access model",
      signal: "Role switching unavailable",
      state: "Single-user",
      tone: "info",
    },
    {
      description: status?.app ?? "Workbench API",
      detail: `Database ${status?.database_status ?? "not reported"}; schema ${
        status?.schema_status ?? "not reported"
      }.`,
      id: "backend-service",
      label: "Backend service",
      signal: status?.core_version
        ? `Core ${status.core_version}`
        : "Core version not reported",
      state: backend.label,
      tone: backend.tone,
    },
    {
      description: "NVD, EPSS, KEV readiness",
      detail: providerSnapshotSummary(providerStatus),
      id: "provider-snapshot",
      label: "Provider snapshot",
      signal: `Cache ${formatCacheAge(providerStatus?.cache_age_seconds)}`,
      state: provider.label,
      tone: provider.tone,
    },
    {
      description: "Bundle generation basis",
      detail: providerStatus?.last_sync
        ? `Last provider sync ${formatDateTime(providerStatus.last_sync)}.`
        : "No provider sync timestamp has been reported.",
      id: "evidence-readiness",
      label: "Evidence readiness",
      signal: providerStatus?.snapshot_mode ?? "Snapshot mode not reported",
      state: evidence.label,
      tone: evidence.tone,
    },
    {
      description: "Safe operational signal",
      detail: latestError,
      id: "api-errors",
      label: "Latest API error",
      signal: "Credentials are never displayed",
      state: latestError === "None" ? "None" : "Review",
      tone: latestError === "None" ? "success" : "critical",
    },
  ]
}

function backendState(
  status: string | null | undefined,
  statusError: string,
): { label: string; tone: VpwBadgeTone } {
  if (statusError) {
    return { label: "Needs review", tone: "critical" }
  }
  if (!status) {
    return { label: "Checking", tone: "info" }
  }
  if (status === "ready") {
    return { label: "Ready", tone: "success" }
  }
  return { label: status, tone: "warning" }
}
