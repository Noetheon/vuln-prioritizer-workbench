import { Outlet, useLocation, useNavigate } from "@tanstack/react-router"
import { useEffect } from "react"
import { RemediationQueue } from "../../components/findings/RemediationQueue"
import { useFindingsRouteState } from "../../components/findings/useFindingsRouteState"
import { apiErrorMessage } from "../../lib/app-errors"
import { useWorkbenchContext } from "../WorkbenchContext"
import {
  cleanFindingsSearchQueryString,
  findingsSearchToApiParams,
  findingsSearchToUrlSearch,
  parseFindingsSearch,
  type FindingsSearchState,
} from "../../components/findings/findings-search-state"
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
  const findingsSearch = parseFindingsSearch(location.searchStr)
  const cleanedSearch = cleanFindingsSearchQueryString(location.searchStr)
  const currentSearch = location.searchStr.startsWith("?")
    ? location.searchStr.slice(1)
    : location.searchStr

  function updateFindingsSearch(nextSearch: FindingsSearchState) {
    void navigate({
      search: findingsSearchToUrlSearch(nextSearch),
      to: "/findings",
    })
  }

  useEffect(() => {
    if (searchQueryStringsEqual(currentSearch, cleanedSearch)) {
      return
    }
    void navigate({
      replace: true,
      search: findingsSearchToUrlSearch(parseFindingsSearch(cleanedSearch)),
      to: "/findings",
    })
  }, [cleanedSearch, currentSearch, navigate])

  const {
    activeFindingFilters,
    clearFindingAssetFilter,
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
    updateFindingSortDirection,
  } = useFindingsRouteState({
    onSearchChange: updateFindingsSearch,
    search: findingsSearch,
  })
  const projectSummaryQuery = useProjectSummaryQuery(selectedProjectId)
  const findingsQueryParams = findingsSearchToApiParams(
    findingsSearch,
    selectedProjectId,
  )
  const findingsQuery = useFindingsQuery(
    findingsQueryParams,
    Boolean(selectedProjectId),
  )
  const findings = findingsQuery.data?.data ?? []
  const findingCount = findingsQuery.data?.count ?? 0

  return (
    <section
      aria-label="Findings Remediation Queue"
      className="w-full"
    >
      <RemediationQueue
        activeFindingFilters={activeFindingFilters}
        findingAssetId={findingsSearch.assetId || null}
        findingAssetKey={findingsSearch.assetKey || null}
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
        findingSearch={findingsSearchToUrlSearch(findingsSearch)}
        onClearAssetFilter={clearFindingAssetFilter}
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
        onSortDirectionChange={updateFindingSortDirection}
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

function searchQueryStringsEqual(left: string, right: string) {
  return normalizedSearchEntries(left) === normalizedSearchEntries(right)
}

function normalizedSearchEntries(value: string) {
  return Array.from(new URLSearchParams(value).entries())
    .sort(([leftKey, leftValue], [rightKey, rightValue]) =>
      `${leftKey}\u0000${leftValue}`.localeCompare(
        `${rightKey}\u0000${rightValue}`,
      ),
    )
    .map(([key, entryValue]) => `${key}=${entryValue}`)
    .join("&")
}
