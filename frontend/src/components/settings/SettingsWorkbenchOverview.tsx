import {
  VpwBadge,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwSkeletonStack,
  VpwStatusBanner,
  VpwTableCard,
  type VpwBadgeTone,
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

const settingsStateColumns: VpwDataTableColumn<SettingsStateRow>[] = [
  {
    id: "setting",
    header: "Setting",
    width: "26%",
    cell: (row) => (
      <div className="vpw-table-cell-stack">
        <span className="vpw-table-cell-primary">{row.label}</span>
        <span className="vpw-table-cell-secondary">{row.description}</span>
      </div>
    ),
  },
  {
    id: "state",
    header: "State",
    width: "16%",
    cell: (row) => <VpwBadge tone={row.tone}>{row.state}</VpwBadge>,
  },
  {
    id: "detail",
    header: "Details",
    cell: (row) => (
      <span className="text-sm text-[var(--vpw-text-secondary)]">
        {row.detail}
      </span>
    ),
  },
  {
    id: "signal",
    header: "Signal",
    width: "24%",
    cell: (row) => (
      <span className="text-sm font-medium text-[var(--vpw-text-primary)]">
        {row.signal}
      </span>
    ),
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
          ariaLabel="Workspace settings state"
          caption="Workspace settings state"
          columns={settingsStateColumns}
          data={settingsStateRows({
            providerStatus,
            providerStatusError,
            status,
            statusError,
          })}
          density="compact"
          getRowKey={(row) => row.id}
          minWidth="860px"
        />
      )}

      {errorMessage ? (
        <VpwStatusBanner title="Settings need review" tone="critical">
          {errorMessage}
        </VpwStatusBanner>
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
      id: "workspace-profile",
      label: "Workspace profile",
      description: "Local operator scope",
      state: "Local workspace",
      detail: "This browser is connected directly to the local Workbench.",
      signal: "No remote tenancy configured",
      tone: "success",
    },
    {
      id: "access-model",
      label: "Access model",
      description: "Operator mode",
      state: "Single-user",
      detail: "The local operator can manage imports, evidence, and settings.",
      signal: "Role switching unavailable",
      tone: "info",
    },
    {
      id: "backend-service",
      label: "Backend service",
      description: status?.app ?? "Workbench API",
      state: backend.label,
      detail: `Database ${status?.database_status ?? "not reported"}; schema ${
        status?.schema_status ?? "not reported"
      }.`,
      signal: status?.core_version
        ? `Core ${status.core_version}`
        : "Core version not reported",
      tone: backend.tone,
    },
    {
      id: "provider-snapshot",
      label: "Provider snapshot",
      description: "NVD, EPSS, KEV readiness",
      state: provider.label,
      detail: providerSnapshotSummary(providerStatus),
      signal: `Cache ${formatCacheAge(providerStatus?.cache_age_seconds)}`,
      tone: provider.tone,
    },
    {
      id: "evidence-readiness",
      label: "Evidence readiness",
      description: "Bundle generation basis",
      state: evidence.label,
      detail: providerStatus?.last_sync
        ? `Last provider sync ${formatDateTime(providerStatus.last_sync)}.`
        : "No provider sync timestamp has been reported.",
      signal: providerStatus?.snapshot_mode ?? "Snapshot mode not reported",
      tone: evidence.tone,
    },
    {
      id: "api-errors",
      label: "Latest API error",
      description: "Safe operational signal",
      state: latestError === "None" ? "None" : "Review",
      detail: latestError,
      signal: "Credentials are never displayed",
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
