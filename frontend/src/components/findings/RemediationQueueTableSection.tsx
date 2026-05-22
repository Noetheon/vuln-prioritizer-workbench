import { ChevronLeft, ChevronRight } from "lucide-react"
import type { FindingPublic, ProjectPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  DataTableFrame,
  VpwField,
  VpwSelectControl,
} from "@/components/vpw"
import { buildFindingsDataTableColumns } from "./FindingsDataTableColumns"
import type { FindingsUrlSearch } from "./findings-search-state"
import {
  type FindingsDirection,
  type QueueSort,
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
  const columns = buildFindingsDataTableColumns({
    findingDirection,
    findingSearch,
    onOpenSheet,
    onSort: onUpdateColumnSort,
    queueSort,
  })

  return (
    <DataTableFrame
      actions={
        !isDemo ? (
          <VpwField
            className="vpw-filter-field vpw-filter-field--sm"
            label="Rows"
          >
            <VpwSelectControl
              ariaLabel="Rows"
              onValueChange={(value) => onPageSizeChange(Number(value))}
              options={pageSizeOptions.map((size) => ({
                label: String(size),
                value: String(size),
              }))}
              value={String(findingPageSize)}
            />
          </VpwField>
        ) : null
      }
      ariaLabel="Findings remediation queue"
      caption="Findings remediation queue"
      columns={columns}
      data={displayFindings}
      description={`${totalCount} prioritized finding${
        totalCount === 1 ? "" : "s"
      } for ${displayProject?.name ?? "the selected project"}.`}
      eyebrow="Triage focus"
      getRowKey={(finding) => finding.id}
      minWidth="1040px"
      mobileCards={false}
      pagination={
        !isDemo ? (
          <>
            <div className="text-sm text-[var(--vpw-text-secondary)]">
              <span aria-live="polite">
                Showing{" "}
                <strong className="font-semibold text-[var(--vpw-text-primary)]">
                  {pageStart}–{pageEnd}
                </strong>{" "}
                of{" "}
                <strong className="font-semibold text-[var(--vpw-text-primary)]">
                  {totalCount}
                </strong>
              </span>
            </div>
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <Button
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
                disabled={
                  findingsLoading ||
                  findingOffset + findingPageSize >= findingCount
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
          </>
        ) : (
          <p className="text-center text-xs text-[var(--vpw-text-muted)]">
            Demo preview - {displayFindings.length} sample findings shown
          </p>
        )
      }
      tableClassName="table-fixed"
      title="Prioritized findings"
    />
  )
}
