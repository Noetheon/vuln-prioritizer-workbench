import { useQueryClient } from "@tanstack/react-query"
import { ChevronLeft, ChevronRight } from "lucide-react"
import { useState } from "react"
import type { FindingPublic, FindingStatus, ProjectPublic } from "@/api-client"
import { FindingsService } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { apiErrorMessage } from "@/lib/app-errors"
import {
  BULK_STATUS_MAX_FINDINGS,
  bulkStatusOutcomeMessage,
  selectAllState,
  toggleAllSelection,
  toggleSelection,
  visibleSelection,
} from "@/lib/finding-bulk-selection"
import {
  statusRequiresReason,
  statusUpdateRequest,
} from "@/lib/finding-status-transitions"
import { invalidateProjectScopedWorkbenchQueries } from "@/workbench/workbench-query-keys"
import { FindingStatusReasonDialog } from "./FindingStatusReasonDialog"
import { FindingsBulkStatusBar } from "./FindingsBulkStatusBar"
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
  const queryClient = useQueryClient()
  const [selectedIds, setSelectedIds] = useState<ReadonlySet<string>>(
    () => new Set(),
  )
  const [pendingStatus, setPendingStatus] = useState<FindingStatus | null>(null)
  const [bulkPending, setBulkPending] = useState(false)
  const [bulkMessage, setBulkMessage] = useState("")
  const [bulkError, setBulkError] = useState("")
  const visibleIds = displayFindings.map((finding) => finding.id)
  const selected = visibleSelection(selectedIds, visibleIds)
  const projectId = displayProject?.id ?? ""

  function updateSelection(next: ReadonlySet<string>) {
    setSelectedIds(next)
    setBulkMessage("")
    setBulkError("")
  }

  async function applyBulkStatus(status: FindingStatus, reason = "") {
    if (!projectId || selected.length === 0) return
    setBulkPending(true)
    setBulkError("")
    setBulkMessage("")
    try {
      const result = await FindingsService.updateProjectFindingsStatus({
        project_id: projectId,
        findingBulkStatusUpdateRequest: {
          finding_ids: selected.slice(0, BULK_STATUS_MAX_FINDINGS),
          ...statusUpdateRequest(status, reason),
        },
      })
      setPendingStatus(null)
      setSelectedIds(new Set())
      setBulkMessage(bulkStatusOutcomeMessage(result))
      await invalidateProjectScopedWorkbenchQueries(queryClient, projectId)
    } catch (error) {
      setBulkError(apiErrorMessage("Bulk status update failed", error))
    } finally {
      setBulkPending(false)
    }
  }

  function chooseBulkStatus(status: FindingStatus) {
    setBulkError("")
    setBulkMessage("")
    if (statusRequiresReason(status)) {
      setPendingStatus(status)
      return
    }
    void applyBulkStatus(status)
  }

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
        <FindingsBulkStatusBar
          count={selected.length}
          error={pendingStatus === null ? bulkError : ""}
          message={bulkMessage}
          onChooseStatus={chooseBulkStatus}
          onClear={() => updateSelection(new Set())}
          pending={bulkPending}
        />
        <FindingsDataTable
          findingDirection={findingDirection}
          findingSearch={findingSearch}
          findings={displayFindings}
          onOpenSheet={onOpenSheet}
          onSort={onUpdateColumnSort}
          queueSort={queueSort}
          selection={
            projectId
              ? {
                  allState: selectAllState(selected.length, visibleIds.length),
                  isSelected: (findingId) => selectedIds.has(findingId),
                  onToggle: (findingId, checked) =>
                    updateSelection(
                      toggleSelection(selectedIds, findingId, checked),
                    ),
                  onToggleAll: (checked) =>
                    updateSelection(toggleAllSelection(visibleIds, checked)),
                }
              : undefined
          }
        />
      </VpwTableCard>
      <FindingStatusReasonDialog
        count={selected.length}
        error={pendingStatus !== null ? bulkError : ""}
        onCancel={() => {
          setPendingStatus(null)
          setBulkError("")
        }}
        onConfirm={(reason) => {
          if (pendingStatus) void applyBulkStatus(pendingStatus, reason)
        }}
        pending={bulkPending}
        status={pendingStatus}
      />

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
