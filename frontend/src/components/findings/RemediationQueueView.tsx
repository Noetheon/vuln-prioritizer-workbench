import type { Dispatch, SetStateAction } from "react"
import type { FindingPublic, ProjectPublic } from "@/api-client"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { FindingsUrlSearch } from "./findings-search-state"
import type { QueueSort } from "./FindingsDataTable"
import type { RemediationQueueProps } from "./RemediationQueue"
import { QuickViewSheet, WhyDialog } from "./RemediationQueueDialogs"
import { RemediationQueueFilters } from "./RemediationQueueFilters"
import { RemediationQueueStates } from "./RemediationQueueStates"
import { DemoBanner, RemediationQueueSummary } from "./RemediationQueueSummary"
import { RemediationQueueTableSection } from "./RemediationQueueTableSection"

type RemediationQueueViewProps = RemediationQueueProps & {
  criticalCount: number
  displayFindings: FindingPublic[]
  displayProject: ProjectPublic | null
  filterCount: number
  hasError: boolean
  highCount: number
  isDemo: boolean
  isLoading: boolean
  kevCount: number
  onOpenSheet: (finding: FindingPublic) => void
  onOpenWhy: (finding: FindingPublic) => void
  onUpdateColumnSort: (sort: QueueSort) => void
  openCount: number
  ownerServiceDraft: string
  pageEnd: number
  pageStart: number
  queueSort: QueueSort
  setAdvancedFiltersOpen: Dispatch<SetStateAction<boolean>>
  setOwnerServiceDraft: Dispatch<SetStateAction<string>>
  setSheetOpen: Dispatch<SetStateAction<boolean>>
  setWhyOpen: Dispatch<SetStateAction<boolean>>
  sheetFinding: FindingPublic | null
  sheetOpen: boolean
  showAdvancedFilters: boolean
  signalFilterCount: number
  totalCount: number
  whyFinding: FindingPublic | null
  whyOpen: boolean
}

export function RemediationQueueView({
  activeFindingFilters,
  criticalCount,
  displayFindings,
  displayProject,
  filterCount,
  findingAssetId,
  findingAssetKey,
  findingCount,
  findingDirection,
  findingFilters,
  findingOffset,
  findingPageSize,
  findingSearch,
  findingsError,
  findingsLoading,
  hasError,
  highCount,
  isDemo,
  isLoading,
  kevCount,
  onClearAssetFilter,
  onClearFilters,
  onFilterChange,
  onOpenSheet,
  onOpenWhy,
  onPageNext,
  onPagePrev,
  onPageSizeChange,
  onProjectChange,
  onUpdateColumnSort,
  openCount,
  ownerServiceDraft,
  pageEnd,
  pageStart,
  projectListLoading,
  projects,
  queueSort,
  selectedProject,
  selectedProjectId,
  setAdvancedFiltersOpen,
  setOwnerServiceDraft,
  setSheetOpen,
  setWhyOpen,
  sheetFinding,
  sheetOpen,
  showAdvancedFilters,
  signalFilterCount,
  totalCount,
  whyFinding,
  whyOpen,
}: RemediationQueueViewProps) {
  const closeSheet = () => setSheetOpen(false)
  const closeWhy = () => setWhyOpen(false)
  const stableFindingSearch: FindingsUrlSearch = findingSearch

  return (
    <TooltipProvider>
      <div
        aria-busy={isLoading}
        aria-live="polite"
        className="findings-remediation-layout flex flex-col gap-5"
      >
        {isDemo ? <DemoBanner /> : null}
        <RemediationQueueSummary
          criticalCount={criticalCount}
          displayProject={displayProject}
          highCount={highCount}
          kevCount={kevCount}
          openCount={openCount}
        />
        <RemediationQueueFilters
          activeFindingFilters={activeFindingFilters}
          filterCount={filterCount}
          findingAssetId={findingAssetId}
          findingAssetKey={findingAssetKey}
          findingFilters={findingFilters}
          isDemo={isDemo}
          onClearAssetFilter={onClearAssetFilter}
          onClearFilters={onClearFilters}
          onFilterChange={onFilterChange}
          onProjectChange={onProjectChange}
          ownerServiceDraft={ownerServiceDraft}
          projectListLoading={projectListLoading}
          projects={projects}
          selectedProjectId={selectedProjectId}
          setAdvancedFiltersOpen={setAdvancedFiltersOpen}
          setOwnerServiceDraft={setOwnerServiceDraft}
          showAdvancedFilters={showAdvancedFilters}
          signalFilterCount={signalFilterCount}
        />
        <RemediationQueueStates
          activeFindingFilters={activeFindingFilters}
          displayFindings={displayFindings}
          findingsError={findingsError}
          hasError={hasError}
          isDemo={isDemo}
          isLoading={isLoading}
          onClearFilters={onClearFilters}
          projects={projects}
          selectedProject={selectedProject}
        />
        <RemediationQueueTableSection
          displayFindings={displayFindings}
          displayProject={displayProject}
          findingCount={findingCount}
          findingDirection={findingDirection}
          findingOffset={findingOffset}
          findingPageSize={findingPageSize}
          findingSearch={stableFindingSearch}
          findingsLoading={findingsLoading}
          isDemo={isDemo}
          onOpenSheet={onOpenSheet}
          onOpenWhy={onOpenWhy}
          onPageNext={onPageNext}
          onPagePrev={onPagePrev}
          onPageSizeChange={onPageSizeChange}
          onUpdateColumnSort={onUpdateColumnSort}
          pageEnd={pageEnd}
          pageStart={pageStart}
          queueSort={queueSort}
          totalCount={totalCount}
        />
        <WhyDialog finding={whyFinding} onClose={closeWhy} open={whyOpen} />
        <QuickViewSheet
          finding={sheetFinding}
          findingSearch={stableFindingSearch}
          onClose={closeSheet}
          open={sheetOpen}
        />
      </div>
    </TooltipProvider>
  )
}
