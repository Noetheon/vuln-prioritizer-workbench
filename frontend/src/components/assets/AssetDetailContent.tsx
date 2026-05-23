import { Edit3, ExternalLink, ListTree, RefreshCw } from "lucide-react"

import type { AssetPublic } from "../../api-client"
import { formatLabel as labelize, optionalText } from "../../lib/ui-copy"
import { Button } from "../ui/button"
import {
  DefinitionList,
  RiskBadge,
  StatusLozenge,
  VpwBadge,
  VpwCommandPanel,
  VpwStatusBanner,
} from "../vpw"
import type { AssetDrawerMode } from "./AssetsRoute"
import {
  assetScoreTone,
  assetFindingsHref,
  environmentTone,
  exposureTone,
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
  const findingCount = selectedAsset.finding_count ?? 0
  const scoreIsCurrent = !selectedAsset.rescore_needed

  return (
    <div className="asset-detail-stack">
      <VpwCommandPanel
        actions={
          <div className="asset-detail-actions">
            <Button
              onClick={() => openAssetDrawer("edit", selectedAsset)}
              type="button"
              variant="outline"
            >
              <Edit3 aria-hidden="true" />
              Edit
            </Button>
            <Button
              onClick={() => openAssetDrawer("linked-findings", selectedAsset)}
              type="button"
              variant="outline"
            >
              <ListTree aria-hidden="true" />
              Findings
            </Button>
            <Button asChild variant="outline">
              <a href={assetFindingsHref(selectedAsset)}>
                <ExternalLink aria-hidden="true" />
                Open
              </a>
            </Button>
          </div>
        }
        className="asset-detail-context"
        description={optionalText(
          selectedAsset.target_ref ?? selectedAsset.asset_key,
        )}
        eyebrow="Asset detail"
        title={selectedAsset.name}
      >
        <div className="asset-detail-badges">
          <RiskBadge level={selectedAsset.criticality} />
          <VpwBadge tone={environmentTone(selectedAsset.environment)}>
            {labelize(selectedAsset.environment)}
          </VpwBadge>
          <VpwBadge tone={exposureTone(selectedAsset.exposure)}>
            {labelize(selectedAsset.exposure)}
          </VpwBadge>
          <VpwBadge tone={assetScoreTone(selectedAsset)}>
            {scoreStatusLabel(selectedAsset)}
          </VpwBadge>
        </div>
      </VpwCommandPanel>

      <DefinitionList
        columns={2}
        density="default"
        items={[
          {
            description: optionalText(selectedAsset.business_service),
            label: "Owner / service",
            value: optionalText(selectedAsset.owner),
          },
          {
            description: `${labelize(selectedAsset.environment)} environment`,
            label: "Exposure",
            tone: exposureTone(selectedAsset.exposure),
            value: labelize(selectedAsset.exposure),
          },
          {
            description: `${findingCount} linked finding${
              findingCount === 1 ? "" : "s"
            }`,
            label: "Highest priority",
            value: highestPriorityBadge(selectedHighestPriority),
          },
          {
            description: scoreIsCurrent
              ? "No recalculation pending"
              : "Recalculate linked findings",
            label: "Scoring state",
            tone: scoreIsCurrent ? "success" : "warning",
            value: scoreStatusLabel(selectedAsset),
          },
        ]}
      />

      <VpwStatusBanner
        action={
          <Button
            aria-busy={assetActionLoading}
            disabled={assetActionLoading || findingCount === 0}
            onClick={() => void recalculateAsset(selectedAsset)}
            type="button"
            variant="outline"
          >
            <RefreshCw aria-hidden="true" />
            Recalculate
          </Button>
        }
        title={scoreStatusLabel(selectedAsset)}
        tone={scoreIsCurrent ? "success" : "warning"}
      >
        Recalculation applies the current asset context to already-linked
        findings in this project.
      </VpwStatusBanner>

      {findingCount === 0 ? (
        <VpwStatusBanner title="No linked findings yet" tone="info">
          Import occurrence data or open Triage after this asset is referenced
          by findings.
        </VpwStatusBanner>
      ) : null}

      <DefinitionList
        columns={2}
        density="default"
        items={[
          {
            label: "Asset key",
            value: selectedAsset.asset_key,
          },
          {
            label: "Target ref",
            value: optionalText(selectedAsset.target_ref),
          },
          {
            label: "Created",
            value: formatDateTime(selectedAsset.created_at),
          },
          {
            label: "Updated",
            value: formatDateTime(selectedAsset.updated_at),
          },
        ]}
      />
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
