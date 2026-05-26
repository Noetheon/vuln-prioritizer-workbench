import { ChevronLeft, ChevronRight } from "lucide-react"
import type { FindingPublic, ProjectPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { FindingsDataTable, type QueueSort } from "./FindingsDataTable"
import type { FindingsUrlSearch } from "./findings-search-state"
import {
  type FindingsDirection,
  pageSizeOptions,
} from "./remediation-queue-model"
import { VpwTableCard } from "@/components/vpw"

type RemediationQueueTableSectionProps = {
  displayFindings: FindingPublic[]
  displayProject: ProjectPublic | null
  findingCount: number
  findingDirection: FindingsDirection
  findingOffset: number
  findingPageSize: number
  findingSearch: FindingsUrlSearch
  findingsLoading: boolean
  onOpenSheet: (finding: FindingPublic) => void
  onPageNext: () => void
  onPagePrev: () => void
  onPageSizeChange: (size: number) => void
  onUpdateColumnSort: (sort: QueueSort) => void
  pageEnd: number
  pageStart: number
  queueSort: QueueSort
  totalCount: number
}

export function RemediationQueueTableSection({
  displayFindings,
  displayProject,
  findingCount,
  findingDirection,
  findingOffset,
  findingPageSize,
  findingSearch,
  findingsLoading,
  onOpenSheet,
  onPageNext,
  onPagePrev,
  onPageSizeChange,
  onUpdateColumnSort,
  pageEnd,
  pageStart,
  queueSort,
  totalCount,
}: RemediationQueueTableSectionProps) {
  if (displayFindings.length === 0) return null

  return (
    <div className="flex flex-col gap-3">
      <VpwTableCard
        actions={
          <div className="findings-rows-control">
            <span>Rows</span>
            <Select
              onValueChange={(v) => onPageSizeChange(Number(v))}
              value={String(findingPageSize)}
            >
              <SelectTrigger
                aria-label="Rows"
                className="findings-filter-control h-9 w-full text-sm"
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {pageSizeOptions.map((s) => (
                  <SelectItem key={s} value={String(s)}>
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        }
        aria-label="Findings remediation queue"
        className="findings-queue-panel"
        description={`${totalCount} prioritized finding${
          totalCount === 1 ? "" : "s"
        } for ${displayProject?.name ?? "the selected project"}.`}
        eyebrow="Triage focus"
        title="Prioritized findings"
      >
        <FindingsDataTable
          findingDirection={findingDirection}
          findingSearch={findingSearch}
          findings={displayFindings}
          onOpenSheet={onOpenSheet}
          onSort={onUpdateColumnSort}
          queueSort={queueSort}
        />
      </VpwTableCard>

      <div className="findings-pagination">
        <div className="findings-pagination__status">
          <span aria-live="polite">
            Showing{" "}
            <strong className="font-semibold text-foreground">
              {pageStart}–{pageEnd}
            </strong>{" "}
            of{" "}
            <strong className="font-semibold text-foreground">
              {totalCount}
            </strong>
          </span>
        </div>
        <div className="findings-pagination__actions">
          <Button
            className="findings-pagination__button"
            disabled={findingsLoading || findingOffset === 0}
            onClick={onPagePrev}
            size="sm"
            type="button"
            variant="outline"
          >
            <ChevronLeft aria-hidden="true" className="mr-1" size={13} />
            Previous
          </Button>
          <Button
            className="findings-pagination__button"
            disabled={
              findingsLoading || findingOffset + findingPageSize >= findingCount
            }
            onClick={onPageNext}
            size="sm"
            type="button"
            variant="outline"
          >
            Next
            <ChevronRight aria-hidden="true" className="ml-1" size={13} />
          </Button>
        </div>
      </div>
    </div>
  )
}
