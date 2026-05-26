import { useCallback, useMemo, useState } from "react"

import type {
  AssetFindingFilter,
  AssetRescoreFilter,
} from "../../components/assets/asset-filter-model.ts"
import {
  assetFiltersFromState,
  defaultAssetFilters,
} from "./assets-route-model.ts"

export function useAssetFilterState() {
  const [assetOwnerFilter, setAssetOwnerFilter] = useState("")
  const [assetServiceFilter, setAssetServiceFilter] = useState("")
  const [assetSearchFilter, setAssetSearchFilter] = useState("")
  const [assetEnvironmentFilter, setAssetEnvironmentFilter] = useState(
    defaultAssetFilters.environment,
  )
  const [assetExposureFilter, setAssetExposureFilter] = useState(
    defaultAssetFilters.exposure,
  )
  const [assetCriticalityFilter, setAssetCriticalityFilter] = useState(
    defaultAssetFilters.criticality,
  )
  const [assetFindingFilter, setAssetFindingFilter] =
    useState<AssetFindingFilter>(defaultAssetFilters.findings)
  const [assetRescoreFilter, setAssetRescoreFilter] =
    useState<AssetRescoreFilter>(defaultAssetFilters.rescore)

  const assetFilters = useMemo(
    () =>
      assetFiltersFromState({
        criticality: assetCriticalityFilter,
        environment: assetEnvironmentFilter,
        exposure: assetExposureFilter,
        findings: assetFindingFilter,
        owner: assetOwnerFilter,
        query: assetSearchFilter,
        rescore: assetRescoreFilter,
        service: assetServiceFilter,
      }),
    [
      assetCriticalityFilter,
      assetEnvironmentFilter,
      assetExposureFilter,
      assetFindingFilter,
      assetOwnerFilter,
      assetRescoreFilter,
      assetSearchFilter,
      assetServiceFilter,
    ],
  )

  const clearAssetFilters = useCallback(() => {
    setAssetOwnerFilter("")
    setAssetServiceFilter("")
    setAssetSearchFilter("")
    setAssetEnvironmentFilter(defaultAssetFilters.environment)
    setAssetExposureFilter(defaultAssetFilters.exposure)
    setAssetCriticalityFilter(defaultAssetFilters.criticality)
    setAssetFindingFilter(defaultAssetFilters.findings)
    setAssetRescoreFilter(defaultAssetFilters.rescore)
  }, [])

  return {
    assetCriticalityFilter,
    assetEnvironmentFilter,
    assetExposureFilter,
    assetFilters,
    assetFindingFilter,
    assetOwnerFilter,
    assetRescoreFilter,
    assetSearchFilter,
    assetServiceFilter,
    clearAssetFilters,
    setAssetCriticalityFilter,
    setAssetEnvironmentFilter,
    setAssetExposureFilter,
    setAssetFindingFilter,
    setAssetOwnerFilter,
    setAssetRescoreFilter,
    setAssetSearchFilter,
    setAssetServiceFilter,
  }
}
