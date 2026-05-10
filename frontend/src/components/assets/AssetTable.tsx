import { RefreshCw } from "lucide-react"

import type { AssetPublic } from "../../api-client"
import { Button } from "../ui/button"
import {
  VpwBadge,
  VpwDataTable,
  type VpwDataTableColumn,
} from "../vpw"
import {
  assetFindingsHref,
  assetScoreTone,
  criticalityTone,
  environmentTone,
  exposureTone,
  findingPriorityTone,
  formatDateTime,
  scoreStatusLabel,
} from "./asset-model"
import { formatLabel as labelize, optionalText } from "../../lib/ui-copy"

export function AssetTable({
  assetActionLoading,
  assets,
  recalculateAsset,
  selectedAssetId,
  selectedHighestPriority,
  setSelectedAssetId,
  startEditAsset,
}: {
  assetActionLoading: boolean
  assets: AssetPublic[]
  recalculateAsset: (asset: AssetPublic) => Promise<void>
  selectedAssetId: string
  selectedHighestPriority: string
  setSelectedAssetId: (assetId: string) => void
  startEditAsset: (asset: AssetPublic) => void
}) {
  const assetColumns: readonly VpwDataTableColumn<AssetPublic>[] = [
    {
      cell: (asset) => (
        <Button
          aria-current={selectedAssetId === asset.id ? "true" : undefined}
          className="h-auto justify-start px-2 py-1 text-left"
          onClick={() => setSelectedAssetId(asset.id)}
          type="button"
          variant="ghost"
        >
          <span className="grid min-w-44 gap-0.5">
            <span className="font-semibold text-[var(--vpw-text-primary)]">
              {asset.name}
            </span>
            <span className="font-mono text-xs text-[var(--vpw-text-muted)]">
              {asset.target_ref ?? asset.asset_key}
            </span>
          </span>
        </Button>
      ),
      header: "Asset / target ref",
      id: "asset",
    },
    {
      cell: (asset) => optionalText(asset.business_service),
      header: "Service",
      id: "service",
    },
    {
      cell: (asset) => optionalText(asset.owner),
      header: "Owner",
      id: "owner",
    },
    {
      cell: (asset) => (
        <VpwBadge tone={environmentTone(asset.environment)}>
          {labelize(asset.environment)}
        </VpwBadge>
      ),
      header: "Environment",
      id: "environment",
    },
    {
      cell: (asset) => (
        <VpwBadge tone={exposureTone(asset.exposure)}>
          {labelize(asset.exposure)}
        </VpwBadge>
      ),
      header: "Exposure",
      id: "exposure",
    },
    {
      cell: (asset) => (
        <VpwBadge tone={criticalityTone(asset.criticality)}>
          {labelize(asset.criticality)}
        </VpwBadge>
      ),
      header: "Criticality",
      id: "criticality",
    },
    {
      cell: (asset) => asset.finding_count ?? 0,
      header: "Findings",
      id: "findings",
    },
    {
      cell: (asset) => {
        const value =
          asset.id === selectedAssetId
            ? selectedHighestPriority
            : asset.finding_count
              ? "Linked"
              : "None"
        return <VpwBadge tone={findingPriorityTone(value)}>{value}</VpwBadge>
      },
      header: "Highest priority",
      id: "highest-priority",
    },
    {
      cell: (asset) => (
        <VpwBadge tone={assetScoreTone(asset)}>
          {scoreStatusLabel(asset)}
        </VpwBadge>
      ),
      header: "Score state",
      id: "score-state",
    },
    {
      cell: (asset) => formatDateTime(asset.updated_at),
      header: "Updated",
      id: "updated",
    },
    {
      cell: (asset) => (
        <div className="flex min-w-52 flex-wrap gap-2">
          <Button asChild size="sm" variant="outline">
            <a href={assetFindingsHref(asset)}>Findings</a>
          </Button>
          <Button
            onClick={() => {
              setSelectedAssetId(asset.id)
              startEditAsset(asset)
            }}
            size="sm"
            type="button"
            variant="outline"
          >
            Edit
          </Button>
          <Button
            aria-label={`Recalculate ${asset.name}`}
            disabled={assetActionLoading || (asset.finding_count ?? 0) === 0}
            onClick={() => void recalculateAsset(asset)}
            size="sm"
            type="button"
            variant="outline"
          >
            <RefreshCw aria-hidden="true" />
            Recalculate
          </Button>
        </div>
      ),
      header: "Actions",
      id: "actions",
    },
  ]

  return (
    <VpwDataTable
      caption="Assets table"
      columns={assetColumns}
      data={assets}
      density="compact"
      getRowKey={(asset) => asset.id}
      minWidth="1120px"
    />
  )
}
