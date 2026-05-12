import type { AssetPublic, FindingPublic } from "../../api-client"
import { formatLabel as labelize } from "../../lib/ui-copy"
import {
  assetFindingsUrlSearch,
  searchStringFromUrlSearch,
} from "../../workbench/selected-project-search"

export function matchesAsset(finding: FindingPublic, asset: AssetPublic) {
  return (
    finding.asset_id === asset.id ||
    finding.asset_key === asset.asset_key ||
    finding.asset_name === asset.name
  )
}

export function findingAssetLabel(finding: FindingPublic) {
  return (
    finding.asset_name ??
    finding.asset_key ??
    finding.business_service ??
    "Unmapped asset"
  )
}

export function assetFindingsHref(asset: AssetPublic) {
  const search = searchStringFromUrlSearch(
    assetFindingsUrlSearch({
      assetId: asset.id,
      assetKey: asset.asset_key,
      projectId: asset.project_id,
    }),
  )
  return `/findings?${search}`
}

export function highestFindingPriority(findings: readonly FindingPublic[]) {
  const order = ["critical", "high", "medium", "low"]
  const priorities = findings
    .map((finding) => String(finding.priority ?? "").toLowerCase())
    .filter(Boolean)
  const highest = order.find((priority) => priorities.includes(priority))
  return highest ? labelize(highest) : "No findings"
}
