import type {
  FindingFilters,
  FindingsDirection,
  FindingsSort,
} from "@/lib/app-defaults"
import {
  clearFindingsFilters,
  findingsSearchHasActiveFilters,
  findingsSearchToFilters,
  type FindingsSearchState,
  updateFindingsSearch,
} from "./findings-search-state"

export type UseFindingsRouteStateOptions = {
  onSearchChange: (nextSearch: FindingsSearchState) => void
  search: FindingsSearchState
}

export function useFindingsRouteState({
  onSearchChange,
  search,
}: UseFindingsRouteStateOptions) {
  const findingFilters = findingsSearchToFilters(search)

  function updateFindingFilter<Key extends keyof FindingFilters>(
    key: Key,
    value: FindingFilters[Key],
  ) {
    onSearchChange(updateFindingsSearch(search, { [key]: value }))
  }

  function clearFindingFilters() {
    onSearchChange(clearFindingsFilters(search))
  }

  function clearFindingAssetFilter() {
    onSearchChange(
      updateFindingsSearch(search, {
        assetId: "",
        assetKey: "",
      }),
    )
  }

  function updateFindingSort(sort: FindingsSort) {
    onSearchChange(updateFindingsSearch(search, { sort }))
  }

  function updateFindingDirection(direction: FindingsDirection) {
    onSearchChange(updateFindingsSearch(search, { direction }))
  }

  function updateFindingSortDirection(
    sort: FindingsSort,
    direction: FindingsDirection,
  ) {
    onSearchChange(updateFindingsSearch(search, { direction, sort }))
  }

  function updateFindingPageSize(size: number) {
    onSearchChange(
      updateFindingsSearch(search, {
        limit: size as FindingsSearchState["limit"],
      }),
    )
  }

  function nextFindingPage() {
    onSearchChange(
      updateFindingsSearch(
        search,
        { offset: search.offset + search.limit },
        { resetOffset: false },
      ),
    )
  }

  function previousFindingPage() {
    onSearchChange(
      updateFindingsSearch(
        search,
        { offset: Math.max(0, search.offset - search.limit) },
        { resetOffset: false },
      ),
    )
  }

  function resetFindingOffset() {
    onSearchChange(
      updateFindingsSearch(search, { offset: 0 }, { resetOffset: false }),
    )
  }

  return {
    activeFindingFilters: findingsSearchHasActiveFilters(search),
    clearFindingAssetFilter,
    clearFindingFilters,
    findingDirection: search.direction,
    findingFilters,
    findingOffset: search.offset,
    findingPageSize: search.limit,
    findingSort: search.sort,
    nextFindingPage,
    previousFindingPage,
    resetFindingOffset,
    updateFindingDirection,
    updateFindingFilter,
    updateFindingPageSize,
    updateFindingSort,
    updateFindingSortDirection,
  }
}

export type UseFindingsRouteState = ReturnType<typeof useFindingsRouteState>
