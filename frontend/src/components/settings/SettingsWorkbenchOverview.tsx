import { Database, KeyRound, ShieldCheck, UserRound } from "lucide-react"

import {
  VpwGrid,
  VpwKeyValueList,
  VpwMetricCard,
  VpwPanel,
  VpwProgress,
  VpwSectionHeader,
  VpwSkeletonStack,
} from "@/components/vpw"
import { formatCacheAge, providerSnapshotSummary } from "@/lib/provider-format"
import {
  activeTokenCount,
  formatDateTime,
  tokenActivityPercent,
} from "./settings-token-model"
import {
  evidenceReadiness,
  providerHealth,
  type SettingsWorkbenchProps,
} from "./settings-workbench-model"

type SettingsMetricsProps = Pick<
  SettingsWorkbenchProps,
  | "apiTokens"
  | "apiTokensLoading"
  | "currentUser"
  | "providerStatus"
  | "providerStatusError"
  | "statusError"
>

type SettingsAccountHealthProps = Pick<
  SettingsWorkbenchProps,
  | "apiTokens"
  | "currentUser"
  | "providerStatus"
  | "providerStatusError"
  | "providerStatusLoading"
  | "status"
  | "statusError"
>

export function SettingsMetrics({
  apiTokens,
  apiTokensLoading,
  currentUser,
  providerStatus,
  providerStatusError,
  statusError,
}: SettingsMetricsProps) {
  const activeTokens = activeTokenCount(apiTokens)
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
          currentUser?.email ??
          (currentUser?.is_active ? "Session active" : "Checking account")
        }
        icon={<UserRound aria-hidden="true" className="h-5 w-5" />}
        label="Signed-in user"
        tone={currentUser?.is_active ? "success" : "warning"}
        value={currentUser ? "Authenticated" : "Loading"}
      />
      <VpwMetricCard
        description={`${activeTokens} active`}
        icon={<KeyRound aria-hidden="true" className="h-5 w-5" />}
        label="API tokens"
        tone={apiTokens.length > 0 ? "info" : "neutral"}
        value={apiTokensLoading ? "Loading" : apiTokens.length}
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

export function SettingsAccountHealth({
  apiTokens,
  currentUser,
  providerStatus,
  providerStatusError,
  providerStatusLoading,
  status,
  statusError,
}: SettingsAccountHealthProps) {
  const provider = providerHealth(providerStatus)

  return (
    <VpwGrid columns={2}>
      <VpwPanel className="space-y-5 p-5">
        <VpwSectionHeader
          description="Current authenticated account and workspace runtime state."
          title="Account and session"
        />
        <VpwKeyValueList
          columns={2}
          items={[
            {
              label: "Signed-in user",
              value: currentUser?.email ?? "Loading user",
            },
            {
              label: "Session state",
              value: currentUser ? "Authenticated" : "Loading",
              tone: currentUser ? "success" : "warning",
            },
            {
              label: "Workspace mode",
              value: status?.app ?? "Workbench",
            },
            {
              label: "Auth mode",
              value: currentUser?.is_superuser
                ? "Admin session"
                : "User session",
              tone: currentUser?.is_superuser ? "support" : "info",
            },
          ]}
        />
      </VpwPanel>

      <VpwPanel className="space-y-5 p-5">
        <VpwSectionHeader
          description="Token inventory, provider health, and reproducibility signals."
          title="Setup health"
        />
        {providerStatusLoading ? (
          <VpwSkeletonStack rows={4} />
        ) : (
          <VpwKeyValueList
            columns={2}
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
        <VpwProgress
          label="Active token coverage"
          tone={apiTokens.length > 0 ? "info" : "neutral"}
          value={tokenActivityPercent(apiTokens)}
        />
      </VpwPanel>
    </VpwGrid>
  )
}
