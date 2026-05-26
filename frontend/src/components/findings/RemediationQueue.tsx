import { useEffect, useRef, useState } from "react"
import type {
  FindingPublic,
  ProjectDecisionSummaryPublic,
  ProjectPublic,
} from "@/api-client"
import type { FindingsUrlSearch } from "./findings-search-state"
import { apiErrorMessage } from "@/lib/app-errors"
import { useFindingDetailQuery } from "@/workbench/useWorkbenchQueries"
import type { QueueSort } from "./FindingsDataTable"
import { RemediationQueueView } from "./RemediationQueueView"
import {
  activeFilterCount,
  advancedFilterCount,
  defaultSortDirections,
  type FindingFilters,
  type FindingsSavedView,
  type FindingsDirection,
  type FindingsSort,
  isApiSort,
} from "./remediation-queue-model"

export type RemediationQueueProps = {
  findings: FindingPublic[]
  findingsLoading: boolean
  findingsError: string
  findingCount: number
  findingOffset: number
  findingPageSize: number
  findingSort: FindingsSort
  findingDirection: FindingsDirection
  findingFilters: FindingFilters
  activeFindingFilters: boolean
  findingAssetId: string | null
  findingAssetKey: string | null
  selectedProject: ProjectPublic | null
  projects: ProjectPublic[]
  projectListLoading: boolean
  projectListError: string
  selectedProjectId: string
  projectSummary: ProjectDecisionSummaryPublic | null
  findingSearch: FindingsUrlSearch
  onClearAssetFilter: () => void
  onFilterChange: <K extends keyof FindingFilters>(
    key: K,
    value: FindingFilters[K],
  ) => void
  onClearFilters: () => void
  onSortDirectionChange: (
    sort: FindingsSort,
    direction: FindingsDirection,
  ) => void
  onDirectionChange: (direction: FindingsDirection) => void
  onPageNext: () => void
  onPagePrev: () => void
  onPageSizeChange: (size: number) => void
  onProjectChange: (id: string) => void
  onSavedViewChange: (view: FindingsSavedView) => void
}

export function RemediationQueue({
  findings,
  findingsLoading,
  findingsError,
  findingCount,
  findingOffset,
  findingPageSize,
  findingSort,
  findingDirection,
  findingFilters,
  activeFindingFilters,
  findingAssetId,
  findingAssetKey,
  selectedProject,
  projects,
  projectListLoading,
  projectListError,
  selectedProjectId,
  projectSummary,
  findingSearch,
  onClearAssetFilter,
  onFilterChange,
  onClearFilters,
  onSortDirectionChange,
  onDirectionChange,
  onPageNext,
  onPagePrev,
  onPageSizeChange,
  onProjectChange,
  onSavedViewChange,
}: RemediationQueueProps) {
  const ownerServiceFilter = findingFilters.ownerService
  const queryFilter = findingFilters.query
  const [ownerServiceDraft, setOwnerServiceDraft] = useState(ownerServiceFilter)
  const [queryDraft, setQueryDraft] = useState(queryFilter)
  const [sheetFinding, setSheetFinding] = useState<FindingPublic | null>(null)
  const [sheetOpen, setSheetOpen] = useState(false)
  const [advancedFiltersOpen, setAdvancedFiltersOpen] = useState(false)
  const sheetTriggerRef = useRef<HTMLElement | null>(null)
  const queueSort: QueueSort = findingSort
  const selectedFindingId = sheetOpen ? (sheetFinding?.id ?? null) : null
  const findingDetailQuery = useFindingDetailQuery(selectedFindingId)

  const displayFindings = findings
  const displaySummary = projectSummary
  const displayProject = selectedProject
  const isLoading = findingsLoading
  const hasError = Boolean(findingsError)

  const criticalCount =
    displaySummary?.counts_by_priority?.critical ??
    displaySummary?.counts_by_priority?.Critical ??
    0
  const highCount =
    displaySummary?.counts_by_priority?.high ??
    displaySummary?.counts_by_priority?.High ??
    0
  const kevCount = displaySummary?.kev_hits ?? 0
  const openCount = displaySummary?.counts_by_status?.open ?? 0

  const pageStart =
    findingCount === 0 ? 0 : Math.min(findingOffset + 1, findingCount)
  const pageEnd = Math.min(findingOffset + findings.length, findingCount)
  const totalCount = findingCount

  const filterCount = activeFilterCount(findingFilters, Boolean(findingAssetId))
  const signalFilterCount = advancedFilterCount(findingFilters)
  const showAdvancedFilters = advancedFiltersOpen || signalFilterCount > 0

  useEffect(() => {
    setOwnerServiceDraft(ownerServiceFilter)
  }, [ownerServiceFilter])

  useEffect(() => {
    setQueryDraft(queryFilter)
  }, [queryFilter])

  useEffect(() => {
    if (ownerServiceDraft === ownerServiceFilter) {
      return
    }

    const timeout = window.setTimeout(() => {
      onFilterChange("ownerService", ownerServiceDraft)
    }, 150)
    return () => window.clearTimeout(timeout)
  }, [onFilterChange, ownerServiceDraft, ownerServiceFilter])

  useEffect(() => {
    if (queryDraft === queryFilter) {
      return
    }

    const timeout = window.setTimeout(() => {
      onFilterChange("query", queryDraft)
    }, 150)
    return () => window.clearTimeout(timeout)
  }, [onFilterChange, queryDraft, queryFilter])

  function openSheet(finding: FindingPublic) {
    if (
      typeof document !== "undefined" &&
      document.activeElement instanceof HTMLElement
    ) {
      sheetTriggerRef.current = document.activeElement
    }
    setSheetFinding(finding)
    setSheetOpen(true)
  }
  function closeSheet() {
    setSheetOpen(false)
    window.setTimeout(() => {
      sheetTriggerRef.current?.focus({ preventScroll: true })
    }, 0)
  }

  function updateColumnSort(sort: QueueSort) {
    const nextDirection =
      queueSort === sort
        ? findingDirection === "asc"
          ? "desc"
          : "asc"
        : defaultSortDirections[sort]
    if (isApiSort(sort)) {
      onSortDirectionChange(sort, nextDirection)
      return
    }
    onDirectionChange(nextDirection)
  }

  const viewProps: RemediationQueueProps = {
    activeFindingFilters,
    findingAssetId,
    findingAssetKey,
    findingCount,
    findingDirection,
    findingFilters,
    findingOffset,
    findingPageSize,
    findingSearch,
    findingSort,
    findings,
    findingsError,
    findingsLoading,
    onClearAssetFilter,
    onClearFilters,
    onDirectionChange,
    onFilterChange,
    onPageNext,
    onPagePrev,
    onPageSizeChange,
    onProjectChange,
    onSavedViewChange,
    onSortDirectionChange,
    projectListError,
    projectListLoading,
    projectSummary,
    projects,
    selectedProject,
    selectedProjectId,
  }

  return (
    <RemediationQueueView
      {...viewProps}
      criticalCount={criticalCount}
      displayFindings={displayFindings}
      displayProject={displayProject}
      filterCount={filterCount}
      hasError={hasError}
      highCount={highCount}
      isLoading={isLoading}
      kevCount={kevCount}
      onOpenSheet={openSheet}
      onUpdateColumnSort={updateColumnSort}
      openCount={openCount}
      ownerServiceDraft={ownerServiceDraft}
      pageEnd={pageEnd}
      pageStart={pageStart}
      queryDraft={queryDraft}
      queueSort={queueSort}
      setAdvancedFiltersOpen={setAdvancedFiltersOpen}
      setOwnerServiceDraft={setOwnerServiceDraft}
      setQueryDraft={setQueryDraft}
      sheetDetail={findingDetailQuery.data?.detail ?? null}
      sheetError={
        findingDetailQuery.isError
          ? apiErrorMessage(
              "Finding detail unavailable",
              findingDetailQuery.error,
            )
          : ""
      }
      sheetExplanation={findingDetailQuery.data?.explanation ?? null}
      sheetExplanationWarning={
        findingDetailQuery.data?.explanationWarning ?? ""
      }
      sheetFinding={sheetFinding}
      sheetLoading={
        Boolean(selectedFindingId) &&
        (findingDetailQuery.isLoading || findingDetailQuery.isFetching)
      }
      sheetOnClose={closeSheet}
      sheetOpen={sheetOpen}
      sheetOnRefresh={() => void findingDetailQuery.refetch()}
      showAdvancedFilters={showAdvancedFilters}
      signalFilterCount={signalFilterCount}
      totalCount={totalCount}
    />
  )
}
