import { Database } from "lucide-react"

import { Button } from "@/components/ui/button"
import {
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwSection,
  VpwSectionHeader,
  SourceMark,
  StatusLozenge,
} from "@/components/vpw"
import type { ProviderSourceRow } from "./providers-workbench-model"

type ProviderSourcesTableProps = {
  onRefreshProviderStatus: () => void
  providerStatusLoading: boolean
  rows: readonly ProviderSourceRow[]
}

export function ProviderSourcesTable({
  onRefreshProviderStatus,
  providerStatusLoading,
  rows,
}: ProviderSourcesTableProps) {
  const columns: readonly VpwDataTableColumn<ProviderSourceRow>[] = [
    {
      cell: (row) => (
        <div className="min-w-40">
          <SourceMark source={row.name} />
          <p className="text-xs text-[var(--vpw-text-muted)]">{row.detail}</p>
        </div>
      ),
      header: "Source",
      id: "source",
    },
    {
      cell: (row) => <StatusLozenge label={row.status} status={row.status} />,
      header: "Status",
      id: "status",
    },
    {
      cell: (row) => row.lastUpdated,
      header: "Last updated",
      id: "last-updated",
    },
    {
      cell: (row) => row.cacheAge,
      header: "Cache age",
      id: "cache-age",
    },
    {
      cell: (row) => row.sourceType,
      header: "Source type",
      id: "source-type",
    },
    {
      cell: (row) => (
        <StatusLozenge
          label={row.usedInEvidence}
          status={row.usedInEvidence === "No" ? "unknown" : "ready"}
        />
      ),
      header: "Used in evidence",
      id: "used-in-evidence",
    },
    {
      cell: () => (
        <Button
          onClick={onRefreshProviderStatus}
          size="sm"
          type="button"
          variant="outline"
        >
          Refresh
        </Button>
      ),
      header: "Actions",
      id: "actions",
    },
  ]

  return (
    <VpwSection>
      <VpwSectionHeader
        description="Configured vulnerability intelligence sources and whether they are available for prioritization evidence."
        eyebrow="Source inventory"
        title="Data source inventory"
      />
      {rows.length === 0 && !providerStatusLoading ? (
        <VpwEmptyState
          action={
            <Button onClick={onRefreshProviderStatus} type="button">
              Refresh status
            </Button>
          }
          description="Refresh provider status to load the latest stored source state."
          icon={<Database aria-hidden="true" />}
          title="No provider sources recorded"
        />
      ) : (
        <VpwDataTable
          caption="Data source inventory"
          columns={columns}
          data={rows}
          density="compact"
          getRowKey={(row) => row.id}
        />
      )}
    </VpwSection>
  )
}
