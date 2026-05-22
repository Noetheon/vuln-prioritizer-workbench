import type { AssetPublic } from "../../api-client"
import { VpwDataTable, VpwTableCard } from "../vpw"
import type { AssetDrawerMode } from "./AssetsRoute"
import { buildAssetColumns } from "./AssetTableColumns"

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
  const assetColumns = buildAssetColumns({
    assetActionLoading,
    openAssetDrawer,
    recalculateAsset,
    selectedAssetId,
    selectedHighestPriority,
    setSelectedAssetId,
    startEditAsset,
  })

  return (
    <VpwTableCard
      className="assets-table-card"
      description={`${assets.length} asset${
        assets.length === 1 ? "" : "s"
      } match the current project and filters.`}
      eyebrow="Register"
      title="Asset register"
    >
      <VpwDataTable
        caption="Assets table"
        columns={assetColumns}
        data={assets}
        density="compact"
        getRowKey={(asset) => asset.id}
        minWidth="1040px"
      />
    </VpwTableCard>
  )
}
