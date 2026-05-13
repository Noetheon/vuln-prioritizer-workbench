import { Link } from "@/lib/router"
import { Activity, FileInput } from "lucide-react"
import type { Dispatch, FormEvent, SetStateAction } from "react"

import type {
  AssetPublic,
  FindingPublic,
  ProjectPublic,
  ProviderStatusPublic,
} from "../../api-client"
import { Button } from "../ui/button"
import { selectedProjectRouteSearch } from "../../workbench/selected-project-search"
import {
  VpwBadge,
  VpwPageContainer,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwStatusBanner,
  VpwToolbar,
  VpwToolbarGroup,
} from "../vpw"
import {
  providerSnapshotHealth,
  providerSnapshotSummary,
} from "../../lib/provider-format"
import { AssetContextForms } from "./AssetContextForm"
import { AssetInventoryShell } from "./AssetFilters"
import { AssetLinkedFindingsPanel } from "./AssetLinkedFindingsPanel"
import { AssetServiceRollup } from "./AssetServiceRollup"
import { AssetSummaryCards } from "./AssetSummaryCards"
import { AssetTable } from "./AssetTable"
import type { AssetFormState, AssetSummary, ServiceRollup } from "./asset-model"

export type AssetsWorkbenchProps = {
  activeProjectLabel: string
  assetActionLoading: boolean
  assetContextFile: File | null
  assetFindings: FindingPublic[]
  assetFindingsError: string
  assetFindingsLoading: boolean
  assetMessage: string
  assetOwnerFilter: string
  assets: AssetPublic[]
  assetsError: string
  assetsLoading: boolean
  assetServiceFilter: string
  assetSummary: AssetSummary
  clearAssetFilters: () => void
  createAsset: (event: FormEvent<HTMLFormElement>) => Promise<void>
  createError: string
  createForm: AssetFormState
  editError: string
  editForm: AssetFormState
  editingAssetId: string
  importAssetContext: (event: FormEvent<HTMLFormElement>) => Promise<void>
  projectLoading: boolean
  projects: ProjectPublic[]
  projectSelectDisabled: boolean
  providerStatus: ProviderStatusPublic | null
  recalculateAsset: (asset: AssetPublic) => Promise<void>
  refreshAssets: (preferredAssetId?: string) => Promise<void>
  saveAsset: (event: FormEvent<HTMLFormElement>) => Promise<void>
  selectProject: (projectId: string) => void
  selectedAsset: AssetPublic | null
  selectedAssetId: string
  selectedHighestPriority: string
  selectedProject: ProjectPublic | null
  selectedProjectId: string
  serviceRollups: ServiceRollup[]
  setAssetContextFile: Dispatch<SetStateAction<File | null>>
  setAssetOwnerFilter: Dispatch<SetStateAction<string>>
  setAssetServiceFilter: Dispatch<SetStateAction<string>>
  setCreateForm: Dispatch<SetStateAction<AssetFormState>>
  setEditForm: Dispatch<SetStateAction<AssetFormState>>
  setSelectedAssetId: Dispatch<SetStateAction<string>>
  startEditAsset: (asset: AssetPublic) => void
}

export function AssetsWorkbench(state: AssetsWorkbenchProps) {
  const projectSearch = selectedProjectRouteSearch(state.selectedProjectId)

  return (
    <VpwPageContainer className="flex flex-col gap-6 px-0 py-0">
        <VpwSection>
          <VpwPanel className="flex flex-col gap-5 p-5">
            <VpwSectionHeader
              description="Manage asset, service, exposure and owner context for risk-based prioritization."
              eyebrow="Asset exposure"
              title="Assets"
            />
            <VpwToolbar label="Asset actions" variant="plain">
              <VpwToolbarGroup>
                <Button asChild>
                  <a href="#asset-context-import">
                    <FileInput aria-hidden="true" data-icon="inline-start" />
                    Import context
                  </a>
                </Button>
                <Button asChild variant="outline">
                  <Link search={projectSearch} to="/findings">
                    View findings
                  </Link>
                </Button>
                <Button
                  aria-label="Refresh assets"
                  disabled={state.assetsLoading}
                  onClick={() => void state.refreshAssets(state.selectedAssetId)}
                  type="button"
                  variant="outline"
                >
                  <Activity aria-hidden="true" data-icon="inline-start" />
                  Refresh
                </Button>
              </VpwToolbarGroup>
            </VpwToolbar>
            <VpwToolbar
              className="overflow-hidden"
              label="Asset page context"
              variant="plain"
            >
              <VpwToolbarGroup className="min-w-0">
                <VpwBadge
                  className="max-w-full whitespace-normal text-left [overflow-wrap:anywhere]"
                  tone="info"
                >
                  Active project: {state.activeProjectLabel}
                </VpwBadge>
                <VpwBadge tone="neutral">
                  Assets: {state.assetSummary.total}
                </VpwBadge>
                <VpwBadge tone="warning">
                  Internet-facing: {state.assetSummary.internetFacing}
                </VpwBadge>
                <VpwBadge tone="critical">
                  Critical services: {state.assetSummary.criticalServices}
                </VpwBadge>
                <VpwBadge tone="support">
                  Owner coverage: {state.assetSummary.ownerCoverage}%
                </VpwBadge>
              </VpwToolbarGroup>
            </VpwToolbar>
            <VpwStatusBanner
              title="Provider snapshot"
              tone={state.providerStatus?.status === "ok" ? "success" : "warning"}
            >
              {providerSnapshotSummary(state.providerStatus)} -{" "}
              {providerSnapshotHealth(state.providerStatus)} - snapshot mode{" "}
              {state.providerStatus?.snapshot_mode ?? "missing"}.
            </VpwStatusBanner>
          </VpwPanel>
        </VpwSection>

        {state.assetsError ? (
          <VpwStatusBanner title="Asset action failed" tone="critical">
            {state.assetsError}
          </VpwStatusBanner>
        ) : null}
        {state.assetMessage ? (
          <VpwStatusBanner title="Asset context updated" tone="success">
            {state.assetMessage}
          </VpwStatusBanner>
        ) : null}
        {state.projectLoading || state.assetsLoading ? (
          <VpwStatusBanner title="Loading asset context" tone="info">
            Refreshing project assets and linked finding counts.
          </VpwStatusBanner>
        ) : null}

        <AssetSummaryCards assetSummary={state.assetSummary} />

        <AssetContextForms
          activeProjectLabel={state.activeProjectLabel}
          assetActionLoading={state.assetActionLoading}
          assetContextFile={state.assetContextFile}
          createAsset={state.createAsset}
          createError={state.createError}
          createForm={state.createForm}
          importAssetContext={state.importAssetContext}
          projectCount={state.projects.length}
          setAssetContextFile={state.setAssetContextFile}
          setCreateForm={state.setCreateForm}
        />

        <AssetInventoryShell
          assetOwnerFilter={state.assetOwnerFilter}
          assetServiceFilter={state.assetServiceFilter}
          assetsLoading={state.assetsLoading}
          clearAssetFilters={state.clearAssetFilters}
          hasAssets={state.assets.length > 0}
          projectLoading={state.projectLoading}
          projects={state.projects}
          projectSelectDisabled={state.projectSelectDisabled}
          refreshAssets={state.refreshAssets}
          selectProject={state.selectProject}
          selectedAssetId={state.selectedAssetId}
          selectedProject={state.selectedProject}
          selectedProjectId={state.selectedProjectId}
          setAssetOwnerFilter={state.setAssetOwnerFilter}
          setAssetServiceFilter={state.setAssetServiceFilter}
        >
          {state.assets.length > 0 ? (
            <AssetTable
              assetActionLoading={state.assetActionLoading}
              assets={state.assets}
              recalculateAsset={state.recalculateAsset}
              selectedAssetId={state.selectedAssetId}
              selectedHighestPriority={state.selectedHighestPriority}
              setSelectedAssetId={state.setSelectedAssetId}
              startEditAsset={state.startEditAsset}
            />
          ) : null}
        </AssetInventoryShell>

        <AssetServiceRollup
          serviceRollups={state.serviceRollups}
          setAssetServiceFilter={state.setAssetServiceFilter}
        />

        {state.selectedAsset ? (
          <AssetLinkedFindingsPanel
            assetActionLoading={state.assetActionLoading}
            assetFindings={state.assetFindings}
            assetFindingsError={state.assetFindingsError}
            assetFindingsLoading={state.assetFindingsLoading}
            editError={state.editError}
            editForm={state.editForm}
            editingAssetId={state.editingAssetId}
            recalculateAsset={state.recalculateAsset}
            saveAsset={state.saveAsset}
            selectedAsset={state.selectedAsset}
            selectedHighestPriority={state.selectedHighestPriority}
            setEditForm={state.setEditForm}
            startEditAsset={state.startEditAsset}
          />
        ) : null}
    </VpwPageContainer>
  )
}
