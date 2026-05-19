import { Link } from "@/lib/router"
import { ArrowUpRight } from "lucide-react"
import type { FindingPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import {
  VpwDataTable,
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSearchInput,
  VpwSurfaceTitle,
} from "@/components/vpw"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import { EmptyState, ErrorState } from "../states"
import { buildDashboardRemediationColumns } from "./DashboardRemediationColumns"

type DashboardRemediationSectionProps = {
  findingsError: string
  findingsLoading: boolean
  onQueueSearchChange: (value: string) => void
  queueFindings: readonly FindingPublic[]
  queueSearch: string
  selectedProjectId: string
}

export function DashboardRemediationSection({
  findingsError,
  findingsLoading,
  onQueueSearchChange,
  queueFindings,
  queueSearch,
  selectedProjectId,
}: DashboardRemediationSectionProps) {
  const previewFindings = queueFindings.slice(0, 5)
  const queueProjectId = selectedProjectId || queueFindings[0]?.project_id || ""
  const fullQueueSearch = selectedProjectRouteSearch(queueProjectId)
  const columns = buildDashboardRemediationColumns()

  return (
    <VpwSurface className="gap-2 py-4">
      <VpwSurfaceHeader>
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <VpwSurfaceTitle>Top Remediation Queue</VpwSurfaceTitle>
            <VpwSurfaceDescription>
              Prioritized items ranked by risk score for immediate action.
            </VpwSurfaceDescription>
          </div>
          <div className="flex w-full flex-col gap-2 sm:w-auto sm:min-w-[30rem] sm:flex-row sm:items-center sm:justify-end">
            <VpwSearchInput
              aria-label="Filter remediation queue"
              className="min-w-0 flex-1 sm:max-w-80"
              onChange={(event) =>
                onQueueSearchChange(event.currentTarget.value)
              }
              placeholder="Filter CVE, owner, component"
              value={queueSearch}
            />
            <Button asChild className="shrink-0" size="sm" variant="outline">
              <Link search={fullQueueSearch} to="/findings">
                View full queue
                <ArrowUpRight aria-hidden="true" className="size-3.5" />
              </Link>
            </Button>
          </div>
        </div>
      </VpwSurfaceHeader>
      <VpwSurfaceBody className="pb-4">
        {findingsLoading ? (
          <div>
            <Skeleton className="h-64" />
          </div>
        ) : findingsError ? (
          <div>
            <ErrorState message={findingsError} />
          </div>
        ) : previewFindings.length === 0 ? (
          <div>
            <EmptyState
              ariaLabel="No remediation queue items"
              compact
              detail={
                queueSearch
                  ? "No rows match the current filter."
                  : "No items are currently available for remediation from this project."
              }
              title={queueSearch ? "No matching findings" : "No findings"}
            />
          </div>
        ) : (
          <VpwDataTable
            ariaLabel="Top remediation queue"
            caption="Dashboard remediation table"
            columns={columns}
            data={previewFindings}
            getRowKey={(finding) => finding.id}
            minWidth="1060px"
            tableClassName="table-fixed"
          />
        )}
      </VpwSurfaceBody>
    </VpwSurface>
  )
}
