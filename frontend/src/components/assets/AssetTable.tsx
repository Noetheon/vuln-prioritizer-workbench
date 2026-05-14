import { Eye, ListTree, RefreshCw } from "lucide-react"

import type { AssetPublic } from "../../api-client"
import { Button } from "../ui/button"
import {
  CountBadge,
  MetaTag,
  RiskBadge,
  StatusLozenge,
  VpwDataTable,
  type VpwDataTableColumn,
} from "../vpw"
import { formatLabel as labelize, optionalText } from "../../lib/ui-copy"
import type { AssetDrawerMode } from "./AssetsRoute"
import { formatDateTime, scoreStatusLabel } from "./asset-model"

export function AssetTable({
  assetActionLoading,
  assets,
  openAssetDrawer,
  recalculateAsset,
  selectedAssetId,
  selectedHighestPriority,
  setSelectedAssetId,
  startEditAsset,
}: {
  assetActionLoading: boolean
  assets: AssetPublic[]
  openAssetDrawer: (
    mode: Exclude<AssetDrawerMode, null>,
    asset?: AssetPublic,
  ) => void
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
      cell: (asset) => (
        <div className="flex min-w-36 flex-wrap gap-1.5">
          <MetaTag label={optionalText(asset.business_service)} />
          <MetaTag label={optionalText(asset.owner)} />
        </div>
      ),
      header: "Service / Owner",
      id: "service-owner",
    },
    {
      cell: (asset) => (
        <div className="flex min-w-36 flex-wrap gap-1.5">
          <MetaTag label={labelize(asset.environment)} />
          <MetaTag label={labelize(asset.exposure)} />
        </div>
      ),
      header: "Environment / Exposure",
      id: "environment-exposure",
    },
    {
      cell: (asset) => (
        <RiskBadge level={asset.criticality} />
      ),
      header: "Criticality",
      id: "criticality",
    },
    {
      cell: (asset) => {
        const value =
          asset.id === selectedAssetId
            ? selectedHighestPriority
            : asset.finding_count
              ? "Linked"
              : "None"
        return (
          <div className="flex min-w-28 flex-wrap gap-1.5">
            <CountBadge value={asset.finding_count ?? 0} />
            {["critical", "high", "medium", "low"].includes(
              value.toLowerCase(),
            ) ? (
              <RiskBadge level={value} />
            ) : (
              <StatusLozenge label={value} status="unknown" />
            )}
          </div>
        )
      },
      header: "Findings",
      id: "findings",
    },
    {
      cell: (asset) => (
        <div className="grid min-w-32 gap-1">
          <StatusLozenge
            label={scoreStatusLabel(asset)}
            status={asset.rescore_needed ? "review_due" : "fresh"}
          />
          <span className="text-xs text-[var(--vpw-text-muted)]">
            {formatDateTime(asset.updated_at)}
          </span>
        </div>
      ),
      header: "Status",
      id: "status",
    },
    {
      cell: (asset) => (
        <div className="flex min-w-64 flex-wrap gap-2">
          <Button
            aria-current={selectedAssetId === asset.id ? "true" : undefined}
            onClick={() => openAssetDrawer("detail", asset)}
            size="sm"
            type="button"
            variant="outline"
          >
            <Eye aria-hidden="true" />
            View
          </Button>
          <Button
            onClick={() => openAssetDrawer("linked-findings", asset)}
            size="sm"
            type="button"
            variant="outline"
          >
            <ListTree aria-hidden="true" />
            Linked findings
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
      minWidth="1040px"
    />
  )
}
