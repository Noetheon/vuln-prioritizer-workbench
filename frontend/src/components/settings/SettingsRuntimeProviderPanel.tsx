import type { ProviderStatusPublic } from "@/api-client"
import { Info } from "lucide-react"

import {
  VpwBadge,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwPanel,
  VpwSectionHeader,
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
    <VpwPanel className="overflow-hidden p-0">
      <div className="border-b border-[var(--vpw-border-subtle)] bg-[color-mix(in_srgb,var(--vpw-bg-panel)_52%,var(--vpw-bg-card))] px-5 py-4">
        <VpwSectionHeader
          description="Safe provider configuration values reported by existing APIs."
          title="Runtime & providers"
        />
      </div>
      <div className="p-4">
        <VpwDataTable
          caption="Provider runtime configuration"
          columns={providerColumns}
          data={providerConfigRows(providerStatus)}
          density="compact"
          getRowKey={(row) => row.id}
        />
      </div>
      <div className="border-t border-[var(--vpw-border-subtle)] bg-[color-mix(in_srgb,var(--vpw-blue)_6%,var(--vpw-bg-card))] px-5 py-3">
        <p className="flex gap-2 text-sm leading-6 text-[var(--vpw-text-secondary)]">
          <Info
            aria-hidden="true"
            className="mt-1 h-4 w-4 shrink-0 text-[var(--vpw-blue)]"
          />
          <span>
            <span className="font-medium text-[var(--vpw-text-primary)]">
              Secrets are not displayed.
            </span>{" "}
            Provider keys, environment secrets, and stored credentials stay outside
            Settings.
          </span>
        </p>
      </div>
    </VpwPanel>
  )
}
