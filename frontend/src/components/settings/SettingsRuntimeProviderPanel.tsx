import type { ProviderStatusPublic, UploadPolicyPublic } from "@/api-client"
import {
  VpwBadge,
  VpwDataTable,
  VpwStatusBanner,
  VpwTableCard,
  type VpwDataTableColumn,
} from "@/components/vpw"
import {
  providerConfigRows,
  type ProviderConfigRow,
} from "./settings-workbench-model"

type RuntimeProviderRow = ProviderConfigRow & {
  category: string
  note: string
}

const runtimeProviderColumns: readonly VpwDataTableColumn<RuntimeProviderRow>[] =
  [
    {
      cell: (row) => (
        <div className="flex min-w-0 flex-col gap-1">
          <span className="font-semibold text-sm text-[var(--vpw-text-primary)]">
            {row.setting}
          </span>
          <span className="vpw-label">{row.category}</span>
        </div>
      ),
      header: "Setting",
      id: "setting",
      width: "24%",
    },
    {
      cell: (row) => <VpwBadge tone={row.tone}>{row.value}</VpwBadge>,
      header: "State",
      id: "state",
      width: "18%",
    },
    {
      cell: (row) => row.detail,
      header: "Detail",
      id: "detail",
    },
    {
      cell: (row) => (
        <span className="font-mono text-xs text-[var(--vpw-text-primary)]">
          {row.note}
        </span>
      ),
      header: "Operational note",
      id: "note",
      width: "24%",
    },
  ]

export function SettingsRuntimeProviderPanel({
  capabilitiesError,
  providerStatus,
  uploadPolicy,
}: {
  capabilitiesError: string
  providerStatus: ProviderStatusPublic | null
  uploadPolicy: UploadPolicyPublic | null
}) {
  const rows = providerConfigRows(
    providerStatus,
    uploadPolicy,
    capabilitiesError,
  ).map(toRuntimeProviderRow)

  return (
    <VpwTableCard
      description="Safe provider configuration values and local execution parameters reported by existing APIs."
      title="Runtime & providers"
    >
      <VpwDataTable
        caption="Runtime and provider settings"
        columns={runtimeProviderColumns}
        data={rows}
        density="comfortable"
        getRowKey={(row) => row.id}
        minWidth="820px"
      />

      <div className="mt-5">
        <VpwStatusBanner title="Secrets are not displayed" tone="info">
          Provider keys, environment secrets, and stored credentials stay
          outside Settings.
        </VpwStatusBanner>
      </div>
    </VpwTableCard>
  )
}

function toRuntimeProviderRow(row: ProviderConfigRow): RuntimeProviderRow {
  return {
    ...row,
    category: providerCategory(row.id),
    note: providerNote(row.id),
  }
}

function providerCategory(id: string) {
  if (id === "nvd" || id === "epss" || id === "kev") {
    return "Security data feed"
  }
  return "Engine parameter"
}

function providerNote(id: string) {
  switch (id) {
    case "nvd":
      return "National Vulnerability DB"
    case "epss":
      return "EPSS probability signal"
    case "kev":
      return "CISA KEV catalog"
    case "snapshot-mode":
      return "Replay behavior"
    case "cache-age":
      return "Freshness window"
    case "upload-size":
      return "Server limit"
    case "request-body-size":
      return "Server limit"
    default:
      return "Reported by backend"
  }
}
