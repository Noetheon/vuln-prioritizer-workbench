import type { AssetPublic } from "../../api-client"

export type AssetSummary = {
  criticalServices: number
  internetFacing: number
  linkedFindings: number
  ownerCoverage: number
  production: number
  total: number
}

export function summarizeAssets(assets: readonly AssetPublic[]): AssetSummary {
  const total = assets.length
  const ownerCount = assets.filter((asset) => asset.owner?.trim()).length
  const criticalServices = new Set(
    assets
      .filter((asset) =>
        ["critical", "high"].includes(String(asset.criticality ?? "")),
      )
      .map((asset) => asset.business_service || asset.name || asset.asset_key),
  ).size

  return {
    criticalServices,
    internetFacing: assets.filter(
      (asset) => asset.exposure === "internet-facing",
    ).length,
    linkedFindings: assets.reduce(
      (totalFindings, asset) => totalFindings + (asset.finding_count ?? 0),
      0,
    ),
    ownerCoverage: total > 0 ? Math.round((ownerCount / total) * 100) : 0,
    production: assets.filter((asset) => asset.environment === "production")
      .length,
    total,
  }
}

export type ServiceRollup = {
  assetCount: number
  criticalAssets: number
  exposure: string
  findings: number
  id: string
  label: string
  owner: string
}

export function buildServiceRollups(
  assets: readonly AssetPublic[],
): ServiceRollup[] {
  const rollups = new Map<string, ServiceRollup>()

  for (const asset of assets) {
    const label = asset.business_service || "Unassigned service"
    const existing = rollups.get(label) ?? {
      assetCount: 0,
      criticalAssets: 0,
      exposure: "unknown",
      findings: 0,
      id: label,
      label,
      owner: "Unassigned",
    }

    existing.assetCount += 1
    existing.findings += asset.finding_count ?? 0
    if (["critical", "high"].includes(String(asset.criticality ?? ""))) {
      existing.criticalAssets += 1
    }
    if (asset.owner && existing.owner === "Unassigned") {
      existing.owner = asset.owner
    }
    if (asset.exposure === "internet-facing") {
      existing.exposure = "internet-facing"
    } else if (
      existing.exposure === "unknown" &&
      asset.exposure &&
      asset.exposure !== "unknown"
    ) {
      existing.exposure = asset.exposure
    }

    rollups.set(label, existing)
  }

  return [...rollups.values()].sort((left, right) => {
    const riskDelta = right.criticalAssets - left.criticalAssets
    return riskDelta !== 0 ? riskDelta : right.findings - left.findings
  })
}
