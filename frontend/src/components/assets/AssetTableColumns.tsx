import { Eye, ListTree, Pencil, RefreshCw } from "lucide-react"
import type { ReactNode } from "react"

import type { AssetPublic } from "../../api-client"
import { Button } from "../ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "../ui/tooltip"
import {
  CountBadge,
  MetaTag,
  RiskBadge,
  StatusLozenge,
  type VpwDataTableColumn,
} from "../vpw"
import { formatLabel as labelize, optionalText } from "../../lib/ui-copy"
import type { AssetDrawerMode } from "./AssetsRoute"
import { formatDateTime, scoreStatusLabel } from "./asset-model"

type BuildAssetColumnsArgs = {
  assetActionLoading: boolean
  openAssetDrawer: (
    mode: Exclude<AssetDrawerMode, null>,
    asset?: AssetPublic,
  ) => void
  recalculateAsset: (asset: AssetPublic) => Promise<void>
  selectedAssetId: string
  selectedHighestPriority: string
  setSelectedAssetId: (assetId: string) => void
  startEditAsset: (asset: AssetPublic) => void
}

export function buildAssetColumns({
  assetActionLoading,
  openAssetDrawer,
  recalculateAsset,
  selectedAssetId,
  selectedHighestPriority,
  setSelectedAssetId,
  startEditAsset,
}: BuildAssetColumnsArgs): readonly VpwDataTableColumn<AssetPublic>[] {
  return [
    {
      cell: (asset) => (
        <Button
          aria-current={selectedAssetId === asset.id ? "true" : undefined}
          className="h-auto justify-start px-2 py-1 text-left"
          onClick={() => setSelectedAssetId(asset.id)}
          type="button"
          variant="ghost"
        >
          <span className="grid min-w-40 gap-0.5">
            <span className="font-semibold text-[var(--vpw-text-primary)]">
              {asset.name}
            </span>
            <span className="font-mono text-xs text-[var(--vpw-text-muted)]">
              {asset.target_ref ?? asset.asset_key}
            </span>
          </span>
        </Button>
      ),
      className: "min-w-44",
      header: "Asset / target ref",
      id: "asset",
      width: "18%",
    },
    {
      cell: (asset) => (
        <div className="flex min-w-32 flex-wrap gap-1.5">
          <MetaTag label={optionalText(asset.business_service)} />
          <MetaTag label={optionalText(asset.owner)} />
        </div>
      ),
      className: "min-w-32",
      header: "Service / Owner",
      id: "service-owner",
      width: "14%",
    },
    {
      cell: (asset) => (
        <div className="flex min-w-32 flex-wrap gap-1.5">
          <MetaTag label={labelize(asset.environment)} />
          <MetaTag label={labelize(asset.exposure)} />
        </div>
      ),
      className: "min-w-36",
      header: "Environment / Exposure",
      id: "environment-exposure",
      width: "16%",
    },
    {
      cell: (asset) => <RiskBadge level={asset.criticality} />,
      className: "min-w-24",
      header: "Criticality",
      id: "criticality",
      width: "8%",
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
          <div className="flex min-w-24 flex-wrap gap-1.5">
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
      className: "min-w-28",
      header: "Findings",
      id: "findings",
      width: "10%",
    },
    {
      cell: (asset) => (
        <div className="grid min-w-28 gap-1">
          <StatusLozenge
            label={scoreStatusLabel(asset)}
            status={asset.rescore_needed ? "review_due" : "fresh"}
          />
          <span className="text-xs text-[var(--vpw-text-muted)]">
            {formatDateTime(asset.updated_at)}
          </span>
        </div>
      ),
      className: "min-w-32",
      header: "Status",
      id: "status",
      width: "15%",
    },
    {
      cell: (asset) => (
        <AssetTableActions
          asset={asset}
          assetActionLoading={assetActionLoading}
          openAssetDrawer={openAssetDrawer}
          recalculateAsset={recalculateAsset}
          selectedAssetId={selectedAssetId}
          setSelectedAssetId={setSelectedAssetId}
          startEditAsset={startEditAsset}
        />
      ),
      className: "min-w-[9rem] text-right",
      header: "Actions",
      headerClassName: "text-right",
      id: "actions",
      width: "9rem",
    },
  ]
}

function AssetTableAction({
  children,
  label,
}: {
  children: ReactNode
  label: string
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}

function AssetTableActions({
  asset,
  assetActionLoading,
  openAssetDrawer,
  recalculateAsset,
  selectedAssetId,
  setSelectedAssetId,
  startEditAsset,
}: Omit<BuildAssetColumnsArgs, "selectedHighestPriority"> & {
  asset: AssetPublic
}) {
  return (
    <div className="vpw-table-actions">
      <AssetTableAction label="View asset">
        <Button
          aria-current={selectedAssetId === asset.id ? "true" : undefined}
          aria-label="View"
          className="vpw-table-action-button"
          onClick={() => openAssetDrawer("detail", asset)}
          size="icon-sm"
          type="button"
          variant="outline"
        >
          <Eye aria-hidden="true" />
        </Button>
      </AssetTableAction>
      <AssetTableAction label="Linked findings">
        <Button
          aria-label={`Open linked findings for ${asset.name}`}
          className="vpw-table-action-button"
          onClick={() => openAssetDrawer("linked-findings", asset)}
          size="icon-sm"
          type="button"
          variant="outline"
        >
          <ListTree aria-hidden="true" />
        </Button>
      </AssetTableAction>
      <AssetTableAction label="Edit asset">
        <Button
          aria-label={`Edit ${asset.name}`}
          className="vpw-table-action-button"
          onClick={() => {
            setSelectedAssetId(asset.id)
            startEditAsset(asset)
          }}
          size="icon-sm"
          type="button"
          variant="outline"
        >
          <Pencil aria-hidden="true" />
        </Button>
      </AssetTableAction>
      <AssetTableAction label="Recalculate asset">
        <Button
          aria-label={`Recalculate ${asset.name}`}
          className="vpw-table-action-button"
          disabled={assetActionLoading || (asset.finding_count ?? 0) === 0}
          onClick={() => void recalculateAsset(asset)}
          size="icon-sm"
          type="button"
          variant="outline"
        >
          <RefreshCw aria-hidden="true" />
        </Button>
      </AssetTableAction>
    </div>
  )
}
