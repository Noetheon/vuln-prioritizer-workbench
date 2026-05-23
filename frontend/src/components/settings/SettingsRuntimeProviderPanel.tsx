import type { ProviderStatusPublic } from "@/api-client"

import {
  VpwBadge,
  VpwDataTable,
  VpwStatusBanner,
  type VpwDataTableColumn,
  VpwTableCard,
} from "@/components/vpw"
import {
  type ProviderConfigRow,
  providerConfigRows,
} from "./settings-workbench-model"

const providerColumns: VpwDataTableColumn<ProviderConfigRow>[] = [
  {
    id: "setting",
    header: "Setting",
    cell: (row) => (
      <p className="font-medium text-[var(--vpw-text-primary)]">
        {row.setting}
      </p>
    ),
  },
  {
    id: "value",
    header: "Value",
    cell: (row) => <VpwBadge tone={row.tone}>{row.value}</VpwBadge>,
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
]

export function SettingsRuntimeProviderPanel({
  providerStatus,
}: {
  providerStatus: ProviderStatusPublic | null
}) {
  return (
    <VpwTableCard
      description="Safe provider configuration values reported by existing APIs."
      title="Runtime & providers"
    >
      <VpwDataTable
        caption="Provider runtime configuration"
        columns={providerColumns}
        data={providerConfigRows(providerStatus)}
        density="compact"
        getRowKey={(row) => row.id}
      />
      <VpwStatusBanner title="Secrets are not displayed" tone="info">
        Provider keys, environment secrets, and stored credentials stay outside
        Settings.
      </VpwStatusBanner>
    </VpwTableCard>
  )
}
