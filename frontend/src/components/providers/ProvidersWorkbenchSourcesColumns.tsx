import { RefreshCw } from "lucide-react"

import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  SourceMark,
  StatusLozenge,
  type VpwDataTableColumn,
} from "@/components/vpw"
import type { ProviderSourceRow } from "./providers-workbench-model"

type BuildProviderSourceColumnsArgs = {
  onRefreshProviderStatus: () => void
  providerStatusLoading: boolean
}

export function buildProviderSourceColumns({
  onRefreshProviderStatus,
  providerStatusLoading,
}: BuildProviderSourceColumnsArgs): readonly VpwDataTableColumn<ProviderSourceRow>[] {
  return [
    {
      cell: (row) => (
        <div className="min-w-40">
          <SourceMark source={row.name} />
          <p className="text-xs text-[var(--vpw-text-muted)]">{row.detail}</p>
        </div>
      ),
      header: "Source",
      id: "source",
      width: "24%",
    },
    {
      cell: (row) => <StatusLozenge label={row.status} status={row.status} />,
      header: "Status",
      id: "status",
      width: "10%",
    },
    {
      cell: (row) => row.lastUpdated,
      header: "Last updated",
      id: "last-updated",
      width: "16%",
    },
    {
      cell: (row) => row.cacheAge,
      header: "Cache age",
      id: "cache-age",
      width: "10%",
    },
    {
      cell: (row) => row.sourceType,
      header: "Source type",
      id: "source-type",
      width: "16%",
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
      width: "14%",
    },
    {
      cell: () => (
        <div className="vpw-table-actions">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                aria-label="Refresh provider status"
                className="vpw-table-action-button"
                disabled={providerStatusLoading}
                onClick={onRefreshProviderStatus}
                size="icon-sm"
                type="button"
                variant="outline"
              >
                <RefreshCw aria-hidden="true" />
              </Button>
            </TooltipTrigger>
            <TooltipContent side="left">Refresh status</TooltipContent>
          </Tooltip>
        </div>
      ),
      className: "min-w-[3.25rem] text-right",
      header: "Actions",
      headerClassName: "text-right",
      id: "actions",
      width: "3.25rem",
    },
  ]
}
