import { Outlet, useLocation, useNavigate } from "@tanstack/react-router"
import type { FindingsReadProjectFindingsData } from "../../api-client"
import { RemediationQueue } from "../../components/findings/RemediationQueue"
import { useFindingsRouteState } from "../../components/findings/useFindingsRouteState"
import { apiErrorMessage } from "../../lib/app-errors"
import { useWorkbenchContext } from "../WorkbenchContext"
import { numericFilterValue } from "../route-utils"
import {
  useFindingsQuery,
  useProjectSummaryQuery,
} from "../useWorkbenchQueries"

function FindingsRouteContainer() {
  const navigate = useNavigate()
  const location = useLocation()
  const {
    projectListLoading,
    projects,
    selectedProject,
    selectedProjectId,
    setSelectedProjectId,
  } = useWorkbenchContext()
  const findingSearchParams = new URLSearchParams(location.search)
  const findingAssetId = findingSearchParams.get("assetId")
  const findingAssetKey = findingSearchParams.get("assetKey")
  const {
    activeFindingFilters,
    clearFindingFilters,
    findingDirection,
    findingFilters,
    findingOffset,
    findingPageSize,
    findingSort,
    nextFindingPage,
    previousFindingPage,
    resetFindingOffset,
    updateFindingDirection,
    updateFindingFilter,
    updateFindingPageSize,
    updateFindingSort,
  } = useFindingsRouteState({
    hasAssetFilter: Boolean(findingAssetId),
    onClearAssetFilter: () => {
      void navigate({ to: "/findings" })
    },
  })
  const projectSummaryQuery = useProjectSummaryQuery(selectedProjectId)
  const findingsQueryParams: FindingsReadProjectFindingsData = {
    asset_id: findingAssetId || undefined,
    cvss_max: numericFilterValue(findingFilters.cvssMax),
    cvss_min: numericFilterValue(findingFilters.cvssMin),
    direction: findingDirection,
    epss_max: numericFilterValue(findingFilters.epssMax),
    epss_min: numericFilterValue(findingFilters.epssMin),
    exposure: findingFilters.exposure || undefined,
    kev:
      findingFilters.kev === "" ? undefined : findingFilters.kev === "true",
    limit: findingPageSize,
    offset: findingOffset,
    owner_service: findingFilters.ownerService.trim() || undefined,
    priority: findingFilters.priority || undefined,
    project_id: selectedProjectId,
    sort: findingSort,
    status: findingFilters.status || undefined,
  }
  const findingsQuery = useFindingsQuery(
    findingsQueryParams,
    Boolean(selectedProjectId),
  )
  const findings = findingsQuery.data?.data ?? []
  const findingCount = findingsQuery.data?.count ?? 0

  return (
    <section
      aria-label="Findings Remediation Queue"
      className="mx-auto w-full max-w-screen-2xl px-4 py-6 sm:px-6"
    >
      <RemediationQueue
        activeFindingFilters={activeFindingFilters}
        findingAssetId={findingAssetId}
        findingAssetKey={findingAssetKey}
        findingCount={findingCount}
        findingDirection={findingDirection}
        findingFilters={findingFilters}
        findingOffset={findingOffset}
        findingPageSize={findingPageSize}
        findingSort={findingSort}
        findings={findings}
        findingsError={
          findingsQuery.isError
            ? apiErrorMessage("Findings unavailable", findingsQuery.error)
            : ""
        }
        findingsLoading={findingsQuery.isLoading || findingsQuery.isFetching}
        onClearFilters={clearFindingFilters}
        onDirectionChange={updateFindingDirection}
        onFilterChange={updateFindingFilter}
        onPageNext={nextFindingPage}
        onPagePrev={previousFindingPage}
        onPageSizeChange={updateFindingPageSize}
        onProjectChange={(id) => {
          resetFindingOffset()
          setSelectedProjectId(id)
        }}
        onSortChange={updateFindingSort}
        projectListLoading={projectListLoading}
        projectSummary={projectSummaryQuery.data ?? null}
        projects={projects}
        selectedProject={selectedProject}
        selectedProjectId={selectedProjectId}
      />
    </section>
  )
}

export function FindingsRoute() {
  const location = useLocation()
  const detailMatch = location.pathname.match(/^\/findings\/([^/]+)$/)
  if (detailMatch) {
    return <Outlet />
  }

  return <FindingsRouteContainer />
}
