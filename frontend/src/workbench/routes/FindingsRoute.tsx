import { Outlet, useLocation, useNavigate } from "@/lib/router"
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
    projectListError,
    projects,
    selectedProject,
    selectedProjectId,
    setSelectedProjectId,
  } = useWorkbenchContext()
  const routeSearch = activeSearchString(location.searchStr)
  const findingsSearch = parseFindingsSearch(routeSearch)
  const cleanedSearch = cleanFindingsSearchQueryString(routeSearch)
  const currentSearch = routeSearch.startsWith("?")
    ? routeSearch.slice(1)
    : routeSearch

  function updateFindingsSearch(nextSearch: FindingsSearchState) {
    void navigate({
      search: findingsRouteSearch(nextSearch, selectedProjectId),
      to: "/findings",
    })
  }

  useEffect(() => {
    if (searchQueryStringsEqual(currentSearch, cleanedSearch)) {
      return
    }
    void navigate({
      replace: true,
      search: findingsRouteSearch(
        parseFindingsSearch(cleanedSearch),
        selectedProjectId,
      ),
      to: "/findings",
    })
  }, [cleanedSearch, currentSearch, navigate, selectedProjectId])

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
        findingSearch={findingsRouteSearch(findingsSearch, selectedProjectId)}
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
        projectListError={projectListError}
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

function findingsRouteSearch(
  findingsSearch: FindingsSearchState,
  selectedProjectId: string,
) {
  return {
    ...findingsSearchToUrlSearch(findingsSearch),
    projectId: selectedProjectId || undefined,
  }
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

function activeSearchString(fallbackSearch: string) {
  return typeof window === "undefined" ? fallbackSearch : window.location.search
}
