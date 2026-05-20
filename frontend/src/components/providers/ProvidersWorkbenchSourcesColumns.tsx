import { Eye } from "lucide-react"

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
  onViewDetails: (row: ProviderSourceRow) => void
}

export function buildProviderSourceColumns({
  onViewDetails,
}: BuildProviderSourceColumnsArgs): readonly VpwDataTableColumn<ProviderSourceRow>[] {
  return [
    {
      cell: (row) => (
        <div className="min-w-40">
          <SourceMark label={row.name} source={row.name} />
          <p className="mt-1 text-xs text-[var(--vpw-text-muted)]">
            {row.technicalName}
          </p>
        </div>
      ),
      header: "Source",
      id: "source",
      width: "18%",
    },
    {
      cell: (row) => row.purpose,
      header: "Purpose",
      id: "purpose",
      width: "18%",
    },
    {
      cell: (row) => (
        <StatusLozenge label={row.statusLabel} status={row.statusToken} />
      ),
      header: "Status",
      id: "status",
      width: "10%",
    },
    {
      cell: (row) => row.lastUpdated,
      header: "Last updated",
      id: "last-updated",
      width: "14%",
    },
    {
      cell: (row) => row.age,
      header: "Age",
      id: "age",
      width: "9%",
    },
    {
      cell: (row) => (
        <StatusLozenge
          label={row.evidenceUse}
          status={row.evidenceUse === "Included" ? "ready" : "unknown"}
        />
      ),
      header: "Evidence use",
      id: "evidence-use",
      width: "12%",
    },
    {
      cell: (row) => row.notes,
      header: "Notes",
      id: "notes",
      width: "20%",
    },
    {
      cell: (row) => (
        <div className="vpw-table-actions">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                aria-label={`View details for ${row.name}`}
                className="vpw-table-action-button"
                onClick={() => onViewDetails(row)}
                size="icon-sm"
                type="button"
                variant="outline"
              >
                <Eye aria-hidden="true" />
              </Button>
            </TooltipTrigger>
            <TooltipContent side="left">View details</TooltipContent>
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
