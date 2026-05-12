import { Database, MonitorCog, ShieldCheck, UserRound } from "lucide-react"

import {
  VpwGrid,
  VpwMetricCard,
  VpwPanel,
  VpwSectionHeader,
  VpwSkeletonStack,
} from "@/components/vpw"
import { formatCacheAge, providerSnapshotSummary } from "@/lib/provider-format"
import {
  evidenceReadiness,
  formatDateTime,
  providerHealth,
  type SettingsWorkbenchProps,
} from "./settings-workbench-model"
import { SettingsFactRows } from "./SettingsFactRows"

type SettingsMetricsProps = Pick<
  SettingsWorkbenchProps,
  "currentUser" | "providerStatus" | "providerStatusError" | "statusError"
>

type SettingsWorkspaceHealthProps = Pick<
  SettingsWorkbenchProps,
  | "currentUser"
  | "providerStatus"
  | "providerStatusError"
  | "providerStatusLoading"
  | "status"
  | "statusError"
>

export function SettingsMetrics({
  currentUser,
  providerStatus,
  providerStatusError,
  statusError,
}: SettingsMetricsProps) {
  const provider = providerHealth(providerStatus)
  const evidence = evidenceReadiness(
    providerStatus,
    providerStatusError,
    statusError,
  )

  return (
    <VpwGrid columns={4}>
      <VpwMetricCard
        description={
          currentUser?.is_active
            ? "This browser uses the local Workbench directly."
            : "Checking workspace readiness."
        }
        icon={<UserRound aria-hidden="true" className="h-5 w-5" />}
        label="Workspace mode"
        tone={currentUser?.is_active ? "success" : "warning"}
        value={currentUser ? "Local" : "Loading"}
      />
      <VpwMetricCard
        description="No login, RBAC, or service-token setup required."
        icon={<MonitorCog aria-hidden="true" className="h-5 w-5" />}
        label="Access mode"
        tone="info"
        value="Single-user"
      />
      <VpwMetricCard
        description={providerSnapshotSummary(providerStatus)}
        icon={<Database aria-hidden="true" className="h-5 w-5" />}
        label="Provider snapshot"
        tone={provider.tone}
        value={provider.label}
      />
      <VpwMetricCard
        description={
          providerStatus?.last_sync
            ? `Last sync ${formatDateTime(providerStatus.last_sync)}`
            : "No sync timestamp"
        }
        icon={<ShieldCheck aria-hidden="true" className="h-5 w-5" />}
        label="Evidence readiness"
        tone={evidence.tone}
        value={evidence.label}
      />
    </VpwGrid>
  )
}

export function SettingsWorkspaceHealth({
  currentUser,
  providerStatus,
  providerStatusError,
  providerStatusLoading,
  status,
  statusError,
}: SettingsWorkspaceHealthProps) {
  const provider = providerHealth(providerStatus)

  return (
    <VpwGrid className="items-start" columns={2}>
      <VpwPanel className="overflow-hidden p-0">
        <div className="border-b border-[var(--vpw-border-subtle)] px-5 py-4">
          <VpwSectionHeader
            description="Current local workspace state."
            title="Workspace access"
          />
        </div>
        <SettingsFactRows
          items={[
            {
              label: "Workspace profile",
              value: currentUser?.is_active ? "Local workspace" : "Loading",
            },
            {
              label: "Access mode",
              value: currentUser ? "Local single-user" : "Loading",
              tone: currentUser ? "success" : "warning",
            },
            {
              label: "Backend mode",
              value: status?.app ?? "Workbench",
            },
            {
              label: "Service tokens",
              value: "Optional for automation",
              tone: "info",
            },
          ]}
        />
      </VpwPanel>

      <VpwPanel className="overflow-hidden p-0">
        <div className="border-b border-[var(--vpw-border-subtle)] px-5 py-4">
          <VpwSectionHeader
            description="Provider health and reproducibility signals."
            title="Setup health"
          />
        </div>
        {providerStatusLoading ? (
          <div className="p-5">
            <VpwSkeletonStack rows={4} />
          </div>
        ) : (
          <SettingsFactRows
            items={[
              {
                label: "Backend status",
                value: status?.status ?? "Not reported",
                tone: status?.status === "ready" ? "success" : "neutral",
              },
              {
                label: "Provider health",
                value: provider.label,
                tone: provider.tone,
              },
              {
                label: "Cache age",
                value: formatCacheAge(providerStatus?.cache_age_seconds),
              },
              {
                label: "Latest API error",
                value:
                  providerStatus?.last_error ||
                  providerStatusError ||
                  statusError ||
                  "None",
                tone:
                  providerStatus?.last_error ||
                  providerStatusError ||
                  statusError
                    ? "critical"
                    : "success",
              },
            ]}
          />
        )}
      </VpwPanel>
    </VpwGrid>
  )
}
