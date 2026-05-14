import {
  type Dispatch,
  type SetStateAction,
  useEffect,
  useState,
} from "react"
import type {
  FindingDetailPublic,
  FindingExplanationPublic,
  FindingPublic,
  ProjectPublic,
} from "@/api-client"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { FindingsUrlSearch } from "./findings-search-state"
import type { QueueSort } from "./FindingsDataTable"
import type { RemediationQueueProps } from "./RemediationQueue"
import { QuickViewSheet } from "./RemediationQueueDialogs"
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
  onUpdateColumnSort: (sort: QueueSort) => void
  openCount: number
  ownerServiceDraft: string
  pageEnd: number
  pageStart: number
  queueSort: QueueSort
  setAdvancedFiltersOpen: Dispatch<SetStateAction<boolean>>
  setOwnerServiceDraft: Dispatch<SetStateAction<string>>
  sheetDetail: FindingDetailPublic | null
  sheetError: string
  sheetExplanation: FindingExplanationPublic | null
  sheetExplanationWarning: string
  sheetFinding: FindingPublic | null
  sheetLoading: boolean
  sheetOnClose: () => void
  sheetOnRefresh: () => void
  sheetOpen: boolean
  showAdvancedFilters: boolean
  signalFilterCount: number
  totalCount: number
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
  onPageNext,
  onPagePrev,
  onPageSizeChange,
  onProjectChange,
  onSavedViewChange,
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
  sheetDetail,
  sheetError,
  sheetExplanation,
  sheetExplanationWarning,
  sheetFinding,
  sheetLoading,
  sheetOnClose,
  sheetOnRefresh,
  sheetOpen,
  showAdvancedFilters,
  signalFilterCount,
  totalCount,
}: RemediationQueueViewProps) {
  const stableFindingSearch: FindingsUrlSearch = findingSearch
  const mobileFilterLayout = useMobileFilterLayout()
  const renderFilters = (controlIdPrefix: string) => (
    <RemediationQueueFilters
      activeFindingFilters={activeFindingFilters}
      controlIdPrefix={controlIdPrefix}
      filterCount={filterCount}
      findingAssetId={findingAssetId}
      findingAssetKey={findingAssetKey}
      findingFilters={findingFilters}
      isDemo={isDemo}
      onClearAssetFilter={onClearAssetFilter}
      onClearFilters={onClearFilters}
      onFilterChange={onFilterChange}
      onProjectChange={onProjectChange}
      onSavedViewChange={onSavedViewChange}
      ownerServiceDraft={ownerServiceDraft}
      projectListLoading={projectListLoading}
      projects={projects}
      selectedProjectId={selectedProjectId}
      setAdvancedFiltersOpen={setAdvancedFiltersOpen}
      setOwnerServiceDraft={setOwnerServiceDraft}
      showAdvancedFilters={showAdvancedFilters}
      signalFilterCount={signalFilterCount}
    />
  )

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
        {!mobileFilterLayout ? renderFilters("queue-desktop") : null}
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
          onPageNext={onPageNext}
          onPagePrev={onPagePrev}
          onPageSizeChange={onPageSizeChange}
          onUpdateColumnSort={onUpdateColumnSort}
          pageEnd={pageEnd}
          pageStart={pageStart}
          queueSort={queueSort}
          totalCount={totalCount}
        />
        {mobileFilterLayout ? renderFilters("queue-mobile") : null}
        <QuickViewSheet
          detail={sheetDetail}
          error={sheetError}
          explanation={sheetExplanation}
          explanationWarning={sheetExplanationWarning}
          finding={sheetFinding}
          findingSearch={stableFindingSearch}
          loading={sheetLoading}
          onClose={sheetOnClose}
          onRefresh={sheetOnRefresh}
          open={sheetOpen}
        />
      </div>
    </TooltipProvider>
  )
}

function useMobileFilterLayout() {
  const [mobileFilterLayout, setMobileFilterLayout] = useState(() => {
    if (typeof window === "undefined") return false
    return window.matchMedia("(max-width: 639px)").matches
  })

  useEffect(() => {
    const media = window.matchMedia("(max-width: 639px)")
    const update = () => setMobileFilterLayout(media.matches)

    update()
    media.addEventListener("change", update)
    return () => media.removeEventListener("change", update)
  }, [])

  return mobileFilterLayout
}
