import type { AssetPublic } from "../../api-client"

export type AssetFindingFilter = "all" | "linked" | "none"
export type AssetRescoreFilter = "all" | "needed" | "current"

export type AssetRegisterFilters = {
  criticality: string
  environment: string
  exposure: string
  findings: AssetFindingFilter
  owner: string
  query: string
  rescore: AssetRescoreFilter
  service: string
}

export const defaultAssetFilters: AssetRegisterFilters = {
  criticality: "all",
  environment: "all",
  exposure: "all",
  findings: "all",
  owner: "",
  query: "",
  rescore: "all",
  service: "",
}

export function filterAssets(
  assets: readonly AssetPublic[],
  filters: AssetRegisterFilters,
): AssetPublic[] {
  const query = normalize(filters.query)
  const owner = normalize(filters.owner)
  const service = normalize(filters.service)

  return assets.filter((asset) => {
    if (
      query &&
      ![
        asset.name,
        asset.asset_key,
        asset.target_ref,
      ].some((value) => includesNormalized(value, query))
    ) {
      return false
    }
    if (service && !includesNormalized(asset.business_service, service)) {
      return false
    }
    if (owner && !includesNormalized(asset.owner, owner)) {
      return false
    }
    if (
      filters.environment !== "all" &&
      asset.environment !== filters.environment
    ) {
      return false
    }
    if (filters.exposure !== "all" && asset.exposure !== filters.exposure) {
      return false
    }
    if (
      filters.criticality !== "all" &&
      asset.criticality !== filters.criticality
    ) {
      return false
    }
    if (filters.findings === "linked" && (asset.finding_count ?? 0) === 0) {
      return false
    }
    if (filters.findings === "none" && (asset.finding_count ?? 0) > 0) {
      return false
    }
    if (filters.rescore === "needed" && !asset.rescore_needed) {
      return false
    }
    if (filters.rescore === "current" && asset.rescore_needed) {
      return false
    }
    return true
  })
}

export function hasActiveAssetFilters(filters: AssetRegisterFilters): boolean {
  return (
    filters.criticality !== defaultAssetFilters.criticality ||
    filters.environment !== defaultAssetFilters.environment ||
    filters.exposure !== defaultAssetFilters.exposure ||
    filters.findings !== defaultAssetFilters.findings ||
    filters.rescore !== defaultAssetFilters.rescore ||
    Boolean(filters.owner.trim()) ||
    Boolean(filters.query.trim()) ||
    Boolean(filters.service.trim())
  )
}

function includesNormalized(value: string | null | undefined, query: string) {
  return normalize(value).includes(query)
}

function normalize(value: string | null | undefined) {
  return String(value ?? "").trim().toLowerCase()
}
