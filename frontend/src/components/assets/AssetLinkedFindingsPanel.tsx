import { Link } from "@/lib/router"
import { Database, RefreshCw } from "lucide-react"
import type { FormEvent } from "react"

import type { AssetPublic, FindingPublic } from "../../api-client"
import { formatLabel as labelize, optionalText } from "../../lib/ui-copy"
import { selectedProjectRouteSearch } from "../../workbench/selected-project-search"
import { Button } from "../ui/button"
import {
  CountBadge,
  MetaTag,
  RiskBadge,
  StatusLozenge,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwKeyValueList,
  VpwPanel,
  VpwSectionHeader,
  VpwSkeletonStack,
  VpwStatusBanner,
  VpwTableCard,
  VpwToolbarGroup,
} from "../vpw"
import { AssetForm } from "./AssetContextForm"
import type { AssetDrawerMode } from "./AssetsRoute"
import {
  type AssetFormState,
  assetFindingsHref,
  findingAssetLabel,
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

export function AssetEditContent({
  assetActionLoading,
  editError,
  editForm,
  saveAsset,
  setEditForm,
}: {
  assetActionLoading: boolean
  editError: string
  editForm: AssetFormState
  saveAsset: (event: FormEvent<HTMLFormElement>) => void
  setEditForm: (form: AssetFormState) => void
}) {
  return (
    <AssetForm
      busy={assetActionLoading}
      buttonLabel="Save Asset"
      disabled={assetActionLoading}
      error={editError}
      form={editForm}
      formLabel="Edit Asset form fields"
      onChange={setEditForm}
      onSubmit={saveAsset}
    />
  )
}

export function AssetLinkedFindingsContent({
  assetFindings,
  assetFindingsError,
  assetFindingsLoading,
  selectedAsset,
}: {
  assetFindings: FindingPublic[]
  assetFindingsError: string
  assetFindingsLoading: boolean
  selectedAsset: AssetPublic
}) {
  const findingColumns: readonly VpwDataTableColumn<FindingPublic>[] = [
    {
      cell: (finding) => <RiskBadge level={finding.priority} />,
      header: "Priority",
      id: "priority",
      width: "7rem",
    },
    {
      cell: (finding) => (
        <Link
          className="font-mono text-sm font-semibold text-[var(--vpw-blue)] hover:underline"
          params={{ findingId: finding.id }}
          search={selectedProjectRouteSearch(finding.project_id)}
          to="/findings/$findingId"
        >
          {finding.cve_id}
        </Link>
      ),
      header: "CVE",
      id: "cve",
      width: "10rem",
    },
    {
      cell: (finding) => optionalText(finding.component_name),
      header: "Component",
      id: "component",
    },
    {
      cell: (finding) => findingAssetLabel(finding),
      header: "Asset",
      id: "asset",
    },
    {
      cell: (finding) => (
        <StatusLozenge
          label={labelize(finding.status)}
          status={finding.status}
        />
      ),
      header: "Status",
      id: "status",
      width: "8rem",
    },
  ]

  return (
    <VpwTableCard
      actions={
        <Button asChild variant="outline">
          <a href={assetFindingsHref(selectedAsset)}>Open findings</a>
        </Button>
      }
      description="Findings returned by the existing project findings API for this asset."
      eyebrow="Linked findings"
      title="Findings for asset"
    >
      {assetFindingsError ? (
        <VpwStatusBanner title="Asset findings unavailable" tone="critical">
          {assetFindingsError}
        </VpwStatusBanner>
      ) : null}
      {assetFindingsLoading ? <VpwSkeletonStack rows={4} /> : null}
      {!assetFindingsLoading && assetFindings.length === 0 ? (
        <VpwEmptyState
          icon={<Database aria-hidden="true" />}
          title={`No findings for ${selectedAsset.name}`}
          description="Import occurrence data that references this asset."
        />
      ) : null}
      {assetFindings.length > 0 ? (
        <VpwDataTable
          caption="Asset findings table"
          columns={findingColumns}
          data={assetFindings}
          density="compact"
          getRowKey={(finding) => finding.id}
          minWidth="760px"
        />
      ) : null}
    </VpwTableCard>
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
