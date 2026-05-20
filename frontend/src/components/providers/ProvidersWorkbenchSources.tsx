import { Database } from "lucide-react"
import { useState } from "react"

import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  StatusLozenge,
  VpwDataTable,
  VpwEmptyState,
  VpwKeyValueList,
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
  const [selectedRow, setSelectedRow] = useState<ProviderSourceRow | null>(null)
  const columns = buildProviderSourceColumns({
    onViewDetails: setSelectedRow,
  })

  return (
    <VpwSection>
      <VpwTableCard
        description="Configured vulnerability intelligence sources and whether they are available for prioritization evidence."
        actions={
          <Button
            aria-busy={providerStatusLoading}
            disabled={providerStatusLoading}
            onClick={onRefreshProviderStatus}
            type="button"
            variant="outline"
          >
            Refresh status
          </Button>
        }
        eyebrow="Data sources"
        title="Source inventory"
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
            minWidth="1120px"
          />
        )}
      </VpwTableCard>
      <Dialog
        onOpenChange={(open) => {
          if (!open) setSelectedRow(null)
        }}
        open={selectedRow !== null}
      >
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{selectedRow?.name ?? "Source details"}</DialogTitle>
            <DialogDescription>
              Source-level provider status and evidence use from the stored
              provider response.
            </DialogDescription>
          </DialogHeader>
          {selectedRow ? (
            <div className="flex flex-col gap-4">
              <StatusLozenge
                label={selectedRow.statusLabel}
                status={selectedRow.statusToken}
              />
              <VpwKeyValueList
                columns={2}
                items={[
                  { label: "Purpose", value: selectedRow.purpose },
                  { label: "Technical name", value: selectedRow.technicalName },
                  { label: "Last updated", value: selectedRow.lastUpdated },
                  { label: "Age", value: selectedRow.age },
                  { label: "Evidence use", value: selectedRow.evidenceUse },
                  { label: "Value", value: selectedRow.value },
                  { label: "Notes", value: selectedRow.notes },
                ]}
              />
            </div>
          ) : null}
        </DialogContent>
      </Dialog>
    </VpwSection>
  )
}
