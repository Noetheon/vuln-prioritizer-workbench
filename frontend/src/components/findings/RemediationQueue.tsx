import { useEffect, useState } from "react"
import type {
  FindingPublic,
  ProjectDecisionSummaryPublic,
  ProjectPublic,
} from "@/api-client"
import type { FindingsUrlSearch } from "./findings-search-state"
import { DEMO_FINDINGS, DEMO_PROJECT, DEMO_SUMMARY } from "@/lib/demo-data"
import { DEMO_MODE_ENABLED } from "@/lib/runtime-config"
import type { QueueSort } from "./FindingsDataTable"
import { RemediationQueueView } from "./RemediationQueueView"
import {
  activeFilterCount,
  advancedFilterCount,
  defaultSortDirections,
  type FindingFilters,
  type FindingsDirection,
  type FindingsSort,
  isApiSort,
  sortDisplayFindings,
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
}: RemediationQueueProps) {
  const ownerServiceFilter = findingFilters.ownerService
  const [ownerServiceDraft, setOwnerServiceDraft] =
    useState(ownerServiceFilter)
  const [whyFinding, setWhyFinding] = useState<FindingPublic | null>(null)
  const [sheetFinding, setSheetFinding] = useState<FindingPublic | null>(null)
  const [whyOpen, setWhyOpen] = useState(false)
  const [sheetOpen, setSheetOpen] = useState(false)
  const [advancedFiltersOpen, setAdvancedFiltersOpen] = useState(false)
  const queueSort: QueueSort = findingSort

  const isDemo =
    DEMO_MODE_ENABLED && projects.length === 0 && !projectListLoading
  const sourceFindings = isDemo ? DEMO_FINDINGS : findings
  const displayFindings = isDemo
    ? sortDisplayFindings(sourceFindings, queueSort, findingDirection)
    : sourceFindings
  const displaySummary = isDemo ? DEMO_SUMMARY : projectSummary
  const displayProject = isDemo ? DEMO_PROJECT : selectedProject
  const isLoading = !isDemo && findingsLoading
  const hasError = !isDemo && Boolean(findingsError)

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

  const pageStart = isDemo
    ? 1
    : findingCount === 0
      ? 0
      : Math.min(findingOffset + 1, findingCount)
  const pageEnd = isDemo
    ? displayFindings.length
    : Math.min(findingOffset + findings.length, findingCount)
  const totalCount = isDemo ? displayFindings.length : findingCount

  const filterCount = activeFilterCount(findingFilters, Boolean(findingAssetId))
  const signalFilterCount = advancedFilterCount(findingFilters)
  const showAdvancedFilters = advancedFiltersOpen || signalFilterCount > 0

  useEffect(() => {
    setOwnerServiceDraft(ownerServiceFilter)
  }, [ownerServiceFilter])

  useEffect(() => {
    if (ownerServiceDraft === ownerServiceFilter) {
      return
    }

    const timeout = window.setTimeout(() => {
      onFilterChange("ownerService", ownerServiceDraft)
    }, 150)
    return () => window.clearTimeout(timeout)
  }, [onFilterChange, ownerServiceDraft, ownerServiceFilter])

  function openWhy(finding: FindingPublic) {
    setWhyFinding(finding)
    setWhyOpen(true)
  }
  function openSheet(finding: FindingPublic) {
    setSheetFinding(finding)
    setSheetOpen(true)
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
    onSortDirectionChange,
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
      isDemo={isDemo}
      isLoading={isLoading}
      kevCount={kevCount}
      onOpenSheet={openSheet}
      onOpenWhy={openWhy}
      onUpdateColumnSort={updateColumnSort}
      openCount={openCount}
      ownerServiceDraft={ownerServiceDraft}
      pageEnd={pageEnd}
      pageStart={pageStart}
      queueSort={queueSort}
      setAdvancedFiltersOpen={setAdvancedFiltersOpen}
      setOwnerServiceDraft={setOwnerServiceDraft}
      setSheetOpen={setSheetOpen}
      setWhyOpen={setWhyOpen}
      sheetFinding={sheetFinding}
      sheetOpen={sheetOpen}
      showAdvancedFilters={showAdvancedFilters}
      signalFilterCount={signalFilterCount}
      totalCount={totalCount}
      whyFinding={whyFinding}
      whyOpen={whyOpen}
    />
  )
}
