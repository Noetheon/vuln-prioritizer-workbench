import {
  Edit3,
  ExternalLink,
  ListTree,
  RefreshCw,
  ShieldCheck,
} from "lucide-react"
import type { ReactNode } from "react"

import type { AssetPublic } from "../../api-client"
import { formatLabel as labelize, optionalText } from "../../lib/ui-copy"
import { Button } from "../ui/button"
import {
  RiskBadge,
  StatusLozenge,
  VpwBadge,
  VpwPanel,
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
      <VpwPanel className="asset-detail-hero">
        <div className="asset-detail-hero__copy">
          <p className="vpw-label text-[var(--vpw-teal)]">Asset detail</p>
          <h3>{selectedAsset.name}</h3>
          <p>
            {optionalText(selectedAsset.target_ref ?? selectedAsset.asset_key)}
          </p>
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
        </div>
        <div className="asset-detail-hero__actions">
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
      </VpwPanel>

      <section aria-label="Asset risk context" className="asset-detail-grid">
        <AssetContextCard
          description={optionalText(selectedAsset.business_service)}
          label="Owner / service"
          value={optionalText(selectedAsset.owner)}
        />
        <AssetContextCard
          description={`${labelize(selectedAsset.environment)} environment`}
          label="Exposure"
          tone={exposureTone(selectedAsset.exposure)}
          value={labelize(selectedAsset.exposure)}
        />
        <AssetContextCard
          description={`${findingCount} linked finding${
            findingCount === 1 ? "" : "s"
          }`}
          label="Highest priority"
          value={highestPriorityBadge(selectedHighestPriority)}
        />
        <AssetContextCard
          description={
            scoreIsCurrent
              ? "No recalculation pending"
              : "Recalculate linked findings"
          }
          label="Scoring state"
          tone={scoreIsCurrent ? "success" : "warning"}
          value={scoreStatusLabel(selectedAsset)}
        />
      </section>

      <VpwPanel className="asset-detail-score-panel">
        <div className="asset-detail-score-panel__copy">
          <ShieldCheck aria-hidden="true" />
          <div>
            <p className="vpw-label">Prioritization state</p>
            <h4>{scoreStatusLabel(selectedAsset)}</h4>
            <p>
              Recalculation applies the current asset context to already-linked
              findings in this project.
            </p>
          </div>
        </div>
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
      </VpwPanel>

      {findingCount === 0 ? (
        <VpwStatusBanner title="No linked findings yet" tone="info">
          Import occurrence data or open Triage after this asset is referenced
          by findings.
        </VpwStatusBanner>
      ) : null}

      <VpwPanel className="asset-detail-metadata-panel">
        <div>
          <p className="vpw-label">Record metadata</p>
          <h4>Identity and lifecycle</h4>
        </div>
        <dl className="asset-detail-metadata-grid">
          <AssetMetadataItem
            label="Asset key"
            value={selectedAsset.asset_key}
          />
          <AssetMetadataItem
            label="Target ref"
            value={optionalText(selectedAsset.target_ref)}
          />
          <AssetMetadataItem
            label="Created"
            value={formatDateTime(selectedAsset.created_at)}
          />
          <AssetMetadataItem
            label="Updated"
            value={formatDateTime(selectedAsset.updated_at)}
          />
        </dl>
      </VpwPanel>
    </div>
  )
}

function AssetContextCard({
  description,
  label,
  tone = "neutral",
  value,
}: {
  description: string
  label: string
  tone?: "neutral" | "success" | "warning" | "critical" | "info" | "support"
  value: ReactNode
}) {
  return (
    <div className="asset-detail-context-card" data-tone={tone}>
      <span className="vpw-label">{label}</span>
      <strong>{value}</strong>
      <small>{description}</small>
    </div>
  )
}

function AssetMetadataItem({
  label,
  value,
}: {
  label: string
  value: ReactNode
}) {
  return (
    <div>
      <dt className="vpw-label">{label}</dt>
      <dd>{value}</dd>
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
