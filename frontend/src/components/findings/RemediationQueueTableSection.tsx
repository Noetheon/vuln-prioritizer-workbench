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
import type { FindingsUrlSearch } from "./findings-search-state"
import { FindingsDataTable, type QueueSort } from "./FindingsDataTable"
import {
  type FindingsDirection,
  pageSizeOptions,
} from "./remediation-queue-model"

type RemediationQueueTableSectionProps = {
  displayFindings: FindingPublic[]
  displayProject: ProjectPublic | null
  findingCount: number
  findingDirection: FindingsDirection
  findingOffset: number
  findingPageSize: number
  findingSearch: FindingsUrlSearch
  findingsLoading: boolean
  isDemo: boolean
  onOpenSheet: (finding: FindingPublic) => void
  onOpenWhy: (finding: FindingPublic) => void
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
  isDemo,
  onOpenSheet,
  onOpenWhy,
  onPageNext,
  onPagePrev,
  onPageSizeChange,
  onUpdateColumnSort,
  pageEnd,
  pageStart,
  queueSort,
  totalCount,
}: RemediationQueueTableSectionProps) {
  if (displayFindings.length === 0) {
    return null
  }

  return (
    <div className="flex flex-col gap-3">
      <section
        aria-label="Findings remediation queue"
        className="top-remediation-panel findings-queue-panel"
      >
        <div className="dashboard-panel-heading">
          <div>
            <span>Remediation Focus</span>
            <h3>Remediation Queue</h3>
            <p>
              {totalCount} prioritized finding{totalCount === 1 ? "" : "s"} for{" "}
              {displayProject?.name ?? "the selected project"}.
            </p>
          </div>
          {!isDemo ? (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <span>Rows</span>
              <Select
                onValueChange={(v) => onPageSizeChange(Number(v))}
                value={String(findingPageSize)}
              >
                <SelectTrigger aria-label="Rows" className="h-8 w-16 text-xs">
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
          ) : null}
        </div>

        <FindingsDataTable
          findingDirection={findingDirection}
          findingSearch={findingSearch}
          findings={displayFindings}
          onOpenSheet={onOpenSheet}
          onOpenWhy={onOpenWhy}
          onSort={onUpdateColumnSort}
          queueSort={queueSort}
        />
      </section>

      {!isDemo ? (
        <div className="flex flex-wrap items-center justify-between gap-3 px-1">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
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
          <div className="flex items-center gap-1.5">
            <Button
              className="h-7"
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
              className="h-7"
              disabled={findingsLoading || findingOffset + findingPageSize >= findingCount}
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
      ) : (
        <p className="text-xs text-center text-muted-foreground">
          Demo preview - {displayFindings.length} sample findings shown
        </p>
      )}
    </div>
  )
}
