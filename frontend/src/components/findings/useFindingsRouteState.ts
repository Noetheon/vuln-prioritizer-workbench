import { useState } from "react"

import {
  defaultFindingFilters,
  type FindingFilters,
  type FindingsDirection,
  type FindingsSort,
  findingPageSizes,
} from "@/lib/app-defaults"

export type UseFindingsRouteStateOptions = {
  hasAssetFilter: boolean
  onClearAssetFilter: () => void
}

function hasActiveFindingFilters(filters: FindingFilters) {
  return Object.values(filters).some((value) => value.trim() !== "")
}

function supportedFindingPageSize(size: number) {
  return findingPageSizes.includes(size as (typeof findingPageSizes)[number])
    ? (size as (typeof findingPageSizes)[number])
    : 10
}

export function useFindingsRouteState({
  hasAssetFilter,
  onClearAssetFilter,
}: UseFindingsRouteStateOptions) {
  const [findingFilters, setFindingFilters] = useState<FindingFilters>(
    defaultFindingFilters,
  )
  const [findingSort, setFindingSort] = useState<FindingsSort>("operational")
  const [findingDirection, setFindingDirection] =
    useState<FindingsDirection>("asc")
  const [findingPageSize, setFindingPageSize] =
    useState<(typeof findingPageSizes)[number]>(10)
  const [findingOffset, setFindingOffset] = useState(0)
  const activeFindingFilters =
    hasActiveFindingFilters(findingFilters) || hasAssetFilter

  function updateFindingFilter<Key extends keyof FindingFilters>(
    key: Key,
    value: FindingFilters[Key],
  ) {
    setFindingOffset(0)
    setFindingFilters((filters) => ({ ...filters, [key]: value }))
  }

  function clearFindingFilters() {
    setFindingOffset(0)
    setFindingFilters(defaultFindingFilters)
    if (hasAssetFilter) {
      onClearAssetFilter()
    }
  }

  function updateFindingSort(sort: FindingsSort) {
    setFindingOffset(0)
    setFindingSort(sort)
  }

  function updateFindingDirection(direction: FindingsDirection) {
    setFindingOffset(0)
    setFindingDirection(direction)
  }

  function updateFindingPageSize(size: number) {
    setFindingOffset(0)
    setFindingPageSize(supportedFindingPageSize(size))
  }

  function nextFindingPage() {
    setFindingOffset((offset) => offset + findingPageSize)
  }

  function previousFindingPage() {
    setFindingOffset((offset) => Math.max(0, offset - findingPageSize))
  }

  function resetFindingOffset() {
    setFindingOffset(0)
  }

  return {
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
  }
}

export type UseFindingsRouteState = ReturnType<typeof useFindingsRouteState>
