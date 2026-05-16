import type { FindingPublic } from "@/api-client"
import { VpwDataTable } from "@/components/vpw"
import { buildFindingsDataTableColumns } from "./FindingsDataTableColumns"
import { FindingsMobileCards } from "./FindingsMobileCards"
import type { FindingsUrlSearch } from "./findings-search-state"
import type { FindingsDirection, QueueSort } from "./remediation-queue-model"

export type { QueueSort } from "./remediation-queue-model"

type FindingsDataTableProps = {
  findings: readonly FindingPublic[]
  findingDirection: FindingsDirection
  findingSearch: FindingsUrlSearch
  onOpenSheet: (finding: FindingPublic) => void
  onSort: (sort: QueueSort) => void
  queueSort: QueueSort
}

export function FindingsDataTable({
  findings,
  findingDirection,
  findingSearch,
  onOpenSheet,
  onSort,
  queueSort,
}: FindingsDataTableProps) {
  const columns = buildFindingsDataTableColumns({
    findingDirection,
    findingSearch,
    onOpenSheet,
    onSort,
    queueSort,
  })

  return (
    <>
      <FindingsMobileCards
        findingSearch={findingSearch}
        findings={findings}
        onOpenSheet={onOpenSheet}
      />
      <div className="finding-table-scroll-shell">
        <VpwDataTable
          ariaLabel="Findings table scroll region"
          caption="Findings remediation queue"
          columns={columns}
          data={findings}
          density="standard"
          getRowKey={(finding) => finding.id}
          minWidth="1040px"
          tableClassName="table-fixed"
        />
      </div>
    </>
  )
}
