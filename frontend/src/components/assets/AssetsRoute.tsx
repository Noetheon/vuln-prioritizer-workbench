import "@/styles/assets.css"

import { Link } from "@/lib/router"
import { Activity, Database, FileInput, FolderKanban, Plus } from "lucide-react"
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
  VpwStatusBanner,
  VpwToolbar,
  VpwToolbarGroup,
} from "../vpw"
import {
  providerSnapshotHealth,
  providerSnapshotSummary,
} from "../../lib/provider-format"
import { AssetDrawer } from "./AssetDrawer"
import { AssetInventoryShell } from "./AssetFilters"
import { AssetServiceRollup } from "./AssetServiceRollup"
import { AssetSummaryCards } from "./AssetSummaryCards"
import { AssetTable } from "./AssetTable"
import type { AssetFormState, AssetSummary, ServiceRollup } from "./asset-model"

export type AssetDrawerMode =
  | "detail"
  | "create"
  | "edit"
  | "import"
  | "linked-findings"
  | null

export type AssetsWorkbenchProps = {
  activeProjectLabel: string
  assetActionLoading: boolean
  assetContextFile: File | null
  assetDrawerMode: AssetDrawerMode
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
  closeAssetDrawer: () => void
  createAsset: (event: FormEvent<HTMLFormElement>) => Promise<void>
  createError: string
  createForm: AssetFormState
  editError: string
  editForm: AssetFormState
  editingAssetId: string
  importAssetContext: (event: FormEvent<HTMLFormElement>) => Promise<void>
  openAssetDrawer: (
    mode: Exclude<AssetDrawerMode, null>,
    asset?: AssetPublic,
  ) => void
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
  const providerHealthy = state.providerStatus?.status === "ok"

  return (
    <VpwPageContainer className="assets-workbench flex flex-col gap-6 px-0 py-0">
      <VpwSection>
        <VpwPanel className="assets-command-panel">
          <div className="assets-command-header">
            <div className="assets-command-copy">
              <p className="vpw-label text-[var(--vpw-teal)]">Asset exposure</p>
              <h2>Asset context workspace</h2>
              <p>
                Maintain ownership, service, exposure, and criticality context
                used by Triage prioritization.
              </p>
            </div>
            <VpwToolbar label="Asset actions" variant="plain">
              <VpwToolbarGroup>
                <Button
                  disabled={state.projects.length === 0}
                  onClick={() => state.openAssetDrawer("create")}
                  type="button"
                >
                  <Plus aria-hidden="true" data-icon="inline-start" />
                  Add asset
                </Button>
                <Button
                  disabled={state.projects.length === 0}
                  onClick={() => state.openAssetDrawer("import")}
                  type="button"
                  variant="outline"
                >
                  <FileInput aria-hidden="true" data-icon="inline-start" />
                  Import assets
                </Button>
                <Button asChild variant="outline">
                  <Link search={projectSearch} to="/findings">
                    View findings
                  </Link>
                </Button>
                <Button
                  aria-label="Refresh assets"
                  disabled={state.assetsLoading}
                  onClick={() =>
                    void state.refreshAssets(state.selectedAssetId)
                  }
                  type="button"
                  variant="outline"
                >
                  <Activity aria-hidden="true" data-icon="inline-start" />
                  Refresh
                </Button>
              </VpwToolbarGroup>
            </VpwToolbar>
          </div>
          <AssetSummaryCards assetSummary={state.assetSummary} />
          <div className="assets-context-strip">
            <div className="assets-context-strip__item">
              <span className="assets-context-strip__icon">
                <FolderKanban aria-hidden="true" />
              </span>
              <div>
                <span className="vpw-label">Active project</span>
                <strong>{state.activeProjectLabel}</strong>
              </div>
            </div>
            <div className="assets-context-strip__item">
              <span
                className="assets-context-strip__icon"
                data-tone={providerHealthy ? "success" : "warning"}
              >
                <Database aria-hidden="true" />
              </span>
              <div>
                <span className="vpw-label">Provider snapshot</span>
                <strong>{providerSnapshotSummary(state.providerStatus)}</strong>
                <small>
                  {providerSnapshotHealth(state.providerStatus)} · snapshot{" "}
                  {state.providerStatus?.snapshot_mode ?? "missing"}
                </small>
              </div>
            </div>
            <VpwBadge tone={providerHealthy ? "success" : "warning"}>
              {providerHealthy ? "Ready for scoring" : "Review provider data"}
            </VpwBadge>
          </div>
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

      <AssetInventoryShell
        assetOwnerFilter={state.assetOwnerFilter}
        assetServiceFilter={state.assetServiceFilter}
        assetsLoading={state.assetsLoading}
        clearAssetFilters={state.clearAssetFilters}
        hasAssets={state.assets.length > 0}
        openImportAssets={() => state.openAssetDrawer("import")}
        projectLoading={state.projectLoading}
        projects={state.projects}
        projectSelectDisabled={state.projectSelectDisabled}
        selectProject={state.selectProject}
        selectedProject={state.selectedProject}
        selectedProjectId={state.selectedProjectId}
        setAssetOwnerFilter={state.setAssetOwnerFilter}
        setAssetServiceFilter={state.setAssetServiceFilter}
      >
        {state.assets.length > 0 ? (
          <AssetTable
            assetActionLoading={state.assetActionLoading}
            assets={state.assets}
            openAssetDrawer={state.openAssetDrawer}
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

      <AssetDrawer state={state} />
    </VpwPageContainer>
  )
}
