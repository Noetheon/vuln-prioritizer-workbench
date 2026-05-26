import type { AssetPublic, FindingPublic, ProjectPublic } from "../../api-client"
import {
  defaultAssetFilters,
  filterAssets,
  hasActiveAssetFilters,
  type AssetFindingFilter,
  type AssetRegisterFilters,
  type AssetRescoreFilter,
} from "../../components/assets/asset-filter-model.ts"
import {
  buildServiceRollups,
  summarizeAssets,
} from "../../components/assets/asset-rollup-model.ts"

const FINDING_PRIORITY_LABELS = new Map([
  ["critical", "Critical"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
])

export type AssetFilterState = {
  criticality: string
  environment: string
  exposure: string
  findings: AssetFindingFilter
  owner: string
  query: string
  rescore: AssetRescoreFilter
  service: string
}

export type AssetMutationPendingState = {
  createPending: boolean
  importPending: boolean
  recalculatePending: boolean
  updatePending: boolean
}

export function assetFiltersFromState(
  state: AssetFilterState,
): AssetRegisterFilters {
  return {
    criticality: state.criticality,
    environment: state.environment,
    exposure: state.exposure,
    findings: state.findings,
    owner: state.owner,
    query: state.query,
    rescore: state.rescore,
    service: state.service,
  }
}

export function assetInventoryView(
  allAssets: readonly AssetPublic[],
  filters: AssetRegisterFilters,
) {
  return {
    assetRecordsTotal: allAssets.length,
    assetSummary: summarizeAssets(allAssets),
    assets: filterAssets(allAssets, filters),
    hasAssetFilters: hasActiveAssetFilters(filters),
    serviceRollups: buildServiceRollups(allAssets),
  }
}

export function selectedAssetForId(
  assets: readonly AssetPublic[],
  selectedAssetId: string,
) {
  return assets.find((asset) => asset.id === selectedAssetId) ?? null
}

export function nextSelectedAssetId(
  assets: readonly AssetPublic[],
  currentAssetId: string,
) {
  return assets.some((asset) => asset.id === currentAssetId)
    ? currentAssetId
    : (assets[0]?.id ?? "")
}

export function activeProjectLabel(
  selectedProject: Pick<ProjectPublic, "name"> | null,
  projectListLoading: boolean,
) {
  return selectedProject?.name ?? (projectListLoading ? "Loading" : "No project")
}

export function projectSelectDisabled(
  projectListLoading: boolean,
  projects: readonly ProjectPublic[],
) {
  return projectListLoading || projects.length === 0
}

export function assetActionLoading({
  createPending,
  importPending,
  recalculatePending,
  updatePending,
}: AssetMutationPendingState) {
  return createPending || updatePending || recalculatePending || importPending
}

export function queryBusy(isLoading: boolean, isFetching: boolean) {
  return isLoading || isFetching
}

export function selectedHighestPriority(findings: readonly FindingPublic[]) {
  const priorities = findings
    .map((finding) => String(finding.priority ?? "").toLowerCase())
    .filter(Boolean)
  for (const [priority, label] of FINDING_PRIORITY_LABELS) {
    if (priorities.includes(priority)) {
      return label
    }
  }
  return "No findings"
}

export { defaultAssetFilters }
