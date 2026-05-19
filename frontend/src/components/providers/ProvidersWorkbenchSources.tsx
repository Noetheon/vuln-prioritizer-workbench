import { Database } from "lucide-react"

import { Button } from "@/components/ui/button"
import {
  VpwDataTable,
  VpwEmptyState,
  VpwSection,
  VpwTableCard,
} from "@/components/vpw"
import { buildProviderSourceColumns } from "./ProvidersWorkbenchSourcesColumns"
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
  const columns = buildProviderSourceColumns({
    onRefreshProviderStatus,
    providerStatusLoading,
  })

  return (
    <VpwSection>
      <VpwTableCard
        description="Configured vulnerability intelligence sources and whether they are available for prioritization evidence."
        eyebrow="Source inventory"
        title="Data source inventory"
      >
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
            minWidth="880px"
          />
        )}
      </VpwTableCard>
    </VpwSection>
  )
}
