import { Link } from "@tanstack/react-router"
import { Database, RefreshCw } from "lucide-react"
import type { FormEvent } from "react"

import type { AssetPublic, FindingPublic } from "../../api-client"
import { formatLabel as labelize, optionalText } from "../../lib/ui-copy"
import { Button } from "../ui/button"
import {
  VpwAssetContextCard,
  VpwBadge,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwGrid,
  VpwKeyValueList,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwSkeletonStack,
  VpwStatusBanner,
  VpwToolbarGroup,
} from "../vpw"
import { AssetForm } from "./AssetContextForm"
import {
  type AssetFormState,
  assetFindingsHref,
  assetScoreTone,
  findingAssetLabel,
  findingPriorityTone,
  findingStatusTone,
  formatDateTime,
  scoreStatusLabel,
} from "./asset-model"

export function AssetLinkedFindingsPanel({
  assetActionLoading,
  assetFindings,
  assetFindingsError,
  assetFindingsLoading,
  editError,
  editForm,
  editingAssetId,
  recalculateAsset,
  saveAsset,
  selectedAsset,
  selectedHighestPriority,
  setEditForm,
  startEditAsset,
}: {
  assetActionLoading: boolean
  assetFindings: FindingPublic[]
  assetFindingsError: string
  assetFindingsLoading: boolean
  editError: string
  editForm: AssetFormState
  editingAssetId: string
  recalculateAsset: (asset: AssetPublic) => Promise<void>
  saveAsset: (event: FormEvent<HTMLFormElement>) => void
  selectedAsset: AssetPublic
  selectedHighestPriority: string
  setEditForm: (form: AssetFormState) => void
  startEditAsset: (asset: AssetPublic) => void
}) {
  const findingColumns: readonly VpwDataTableColumn<FindingPublic>[] = [
    {
      cell: (finding) => (
        <VpwBadge tone={findingPriorityTone(finding.priority)}>
          {labelize(finding.priority)}
        </VpwBadge>
      ),
      header: "Priority",
      id: "priority",
    },
    {
      cell: (finding) => (
        <Link
          className="font-mono text-sm font-semibold text-[var(--vpw-blue)] hover:underline"
          params={{ findingId: finding.id }}
          to="/findings/$findingId"
        >
          {finding.cve_id}
        </Link>
      ),
      header: "CVE",
      id: "cve",
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
        <VpwBadge tone={findingStatusTone(finding.status)}>
          {labelize(finding.status)}
        </VpwBadge>
      ),
      header: "Status",
      id: "status",
    },
  ]

  return (
    <VpwSection>
      <VpwSectionHeader
        actions={
          <VpwToolbarGroup>
            <Button
              onClick={() => startEditAsset(selectedAsset)}
              type="button"
              variant="outline"
            >
              Edit context
            </Button>
            <Button
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
            <Button asChild variant="outline">
              <a href={assetFindingsHref(selectedAsset)}>View findings</a>
            </Button>
          </VpwToolbarGroup>
        }
        description="Selected asset context and linked findings for the active project."
        eyebrow="Asset detail"
        title={selectedAsset.name}
      />
      <VpwGrid columns={2}>
        <div className="space-y-4">
          <VpwAssetContextCard
            asset={selectedAsset.asset_key}
            businessService={optionalText(selectedAsset.business_service)}
            criticality={labelize(selectedAsset.criticality)}
            exposure={labelize(selectedAsset.exposure)}
            owner={optionalText(selectedAsset.owner)}
          />
          <VpwPanel className="space-y-4 p-5">
            <VpwSectionHeader
              eyebrow="Metadata"
              title="Prioritization context"
              description="These fields are used by the Workbench backend when linked findings are recalculated."
            />
            <VpwKeyValueList
              columns={2}
              items={[
                {
                  label: "Target ref",
                  value: optionalText(selectedAsset.target_ref),
                },
                {
                  label: "Findings linked",
                  value: selectedAsset.finding_count ?? 0,
                },
                {
                  label: "Highest priority",
                  value: selectedHighestPriority,
                  tone: findingPriorityTone(selectedHighestPriority),
                },
                {
                  label: "Score state",
                  value: scoreStatusLabel(selectedAsset),
                  tone: assetScoreTone(selectedAsset),
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
        </div>

        <VpwPanel className="space-y-4 p-5">
          {editingAssetId === selectedAsset.id ? (
            <>
              <VpwSectionHeader
                description="Update asset owner, service, exposure, environment and criticality."
                eyebrow="Edit context"
                title="Edit selected asset"
              />
              <AssetForm
                buttonLabel="Save Asset"
                disabled={assetActionLoading}
                error={editError}
                form={editForm}
                formLabel="Edit Asset form fields"
                onChange={setEditForm}
                onSubmit={saveAsset}
              />
            </>
          ) : (
            <>
              <VpwSectionHeader
                description="Open edit mode to update the selected asset context."
                eyebrow="Context editor"
                title="Asset editor"
                actions={
                  <Button
                    onClick={() => startEditAsset(selectedAsset)}
                    type="button"
                    variant="outline"
                  >
                    Edit context
                  </Button>
                }
              />
              <VpwStatusBanner title="Context ready" tone="info">
                Asset edits and recalculation use the existing Workbench asset
                APIs.
              </VpwStatusBanner>
            </>
          )}
        </VpwPanel>
      </VpwGrid>

      <VpwPanel className="space-y-4 p-5">
        <VpwSectionHeader
          actions={
            <Button asChild variant="outline">
              <a href={assetFindingsHref(selectedAsset)}>Open findings</a>
            </Button>
          }
          description="Findings returned by the existing project findings API for this asset."
          eyebrow="Linked findings"
          title="Findings for asset"
        />
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
          />
        ) : null}
      </VpwPanel>
    </VpwSection>
  )
}
