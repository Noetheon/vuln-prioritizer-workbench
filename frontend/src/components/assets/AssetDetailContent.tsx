import { RefreshCw } from "lucide-react"

import type { AssetPublic } from "../../api-client"
import { formatLabel as labelize, optionalText } from "../../lib/ui-copy"
import { Button } from "../ui/button"
import {
  CountBadge,
  MetaTag,
  RiskBadge,
  StatusLozenge,
  VpwKeyValueList,
  VpwPanel,
  VpwSectionHeader,
  VpwStatusBanner,
  VpwToolbarGroup,
} from "../vpw"
import type { AssetDrawerMode } from "./AssetsRoute"
import {
  assetFindingsHref,
  formatDateTime,
  scoreStatusLabel,
} from "./asset-model"

export function AssetDetailContent({
  assetActionLoading,
  openAssetDrawer,
  recalculateAsset,
  selectedAsset,
  selectedHighestPriority,
}: {
  assetActionLoading: boolean
  openAssetDrawer: (
    mode: Exclude<AssetDrawerMode, null>,
    asset?: AssetPublic,
  ) => void
  recalculateAsset: (asset: AssetPublic) => Promise<void>
  selectedAsset: AssetPublic
  selectedHighestPriority: string
}) {
  return (
    <div className="flex flex-col gap-4">
      <VpwPanel className="flex flex-col gap-4 p-5">
        <VpwSectionHeader
          actions={
            <VpwToolbarGroup>
              <Button
                onClick={() => openAssetDrawer("edit", selectedAsset)}
                type="button"
                variant="outline"
              >
                Edit context
              </Button>
              <Button
                onClick={() => openAssetDrawer("linked-findings", selectedAsset)}
                type="button"
                variant="outline"
              >
                Linked findings
              </Button>
              <Button asChild variant="outline">
                <a href={assetFindingsHref(selectedAsset)}>Open findings</a>
              </Button>
            </VpwToolbarGroup>
          }
          description="Asset identity and context used by prioritization after linked findings are recalculated."
          eyebrow="Asset detail"
          title="Asset context"
        />
        <VpwKeyValueList
          columns={2}
          items={[
            { label: "Asset key", value: selectedAsset.asset_key },
            {
              label: "Target ref",
              value: optionalText(selectedAsset.target_ref),
            },
            {
              label: "Owner",
              value: <MetaTag label={optionalText(selectedAsset.owner)} />,
            },
            {
              label: "Business service",
              value: (
                <MetaTag label={optionalText(selectedAsset.business_service)} />
              ),
            },
            {
              label: "Environment",
              value: <MetaTag label={labelize(selectedAsset.environment)} />,
            },
            {
              label: "Exposure",
              value: <MetaTag label={labelize(selectedAsset.exposure)} />,
            },
            {
              label: "Criticality",
              value: <RiskBadge level={selectedAsset.criticality} />,
            },
            {
              label: "Findings linked",
              value: <CountBadge value={selectedAsset.finding_count ?? 0} />,
            },
            {
              label: "Highest priority",
              value: highestPriorityBadge(selectedHighestPriority),
            },
            {
              label: "Score state",
              value: (
                <StatusLozenge
                  label={scoreStatusLabel(selectedAsset)}
                  status={selectedAsset.rescore_needed ? "review_due" : "fresh"}
                />
              ),
            },
            {
              label: "Updated",
              value: formatDateTime(selectedAsset.updated_at),
            },
            {
              label: "Created",
              value: formatDateTime(selectedAsset.created_at),
            },
          ]}
        />
      </VpwPanel>
      <VpwPanel className="flex flex-col gap-4 p-5">
        <VpwSectionHeader
          actions={
            <Button
              aria-busy={assetActionLoading}
              disabled={
                assetActionLoading || (selectedAsset.finding_count ?? 0) === 0
              }
              onClick={() => void recalculateAsset(selectedAsset)}
              type="button"
              variant="outline"
            >
              <RefreshCw aria-hidden="true" />
              Recalculate
            </Button>
          }
          description="Use recalculation after changing context that affects linked finding prioritization."
          eyebrow="Scoring"
          title="Prioritization state"
        />
        <VpwStatusBanner
          title={scoreStatusLabel(selectedAsset)}
          tone={selectedAsset.rescore_needed ? "warning" : "success"}
        >
          Recalculation uses the existing Workbench asset API for already-linked
          findings.
        </VpwStatusBanner>
      </VpwPanel>
    </div>
  )
}

function highestPriorityBadge(priority: string) {
  return ["critical", "high", "medium", "low"].includes(
    priority.toLowerCase(),
  ) ? (
    <RiskBadge level={priority} />
  ) : (
    <StatusLozenge label={priority} status="unknown" />
  )
}
