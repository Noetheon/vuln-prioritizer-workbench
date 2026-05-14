import { Link } from "@/lib/router"
import { Activity, FileInput, Plus } from "lucide-react"
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
import { AssetContextImportForm, AssetForm } from "./AssetContextForm"
import { AssetInventoryShell } from "./AssetFilters"
import { AssetServiceRollup } from "./AssetServiceRollup"
import { AssetSummaryCards } from "./AssetSummaryCards"
import { AssetTable } from "./AssetTable"
import type { AssetFormState, AssetSummary, ServiceRollup } from "./asset-model"
import {
  AssetDetailContent,
  AssetEditContent,
  AssetLinkedFindingsContent,
} from "./AssetLinkedFindingsPanel"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "../ui/sheet"

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
  const drawerTitle = assetDrawerTitle(state)
  const drawerDescription = assetDrawerDescription(state)

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

        <Sheet
          onOpenChange={(open) => {
            if (!open) {
              state.closeAssetDrawer()
            }
          }}
          open={state.assetDrawerMode !== null}
        >
          <SheetContent className="w-[min(100vw,48rem)] overflow-y-auto sm:max-w-none">
            <SheetHeader>
              <SheetTitle>{drawerTitle}</SheetTitle>
              <SheetDescription>{drawerDescription}</SheetDescription>
            </SheetHeader>
            <AssetDrawerContent state={state} />
          </SheetContent>
        </Sheet>
    </VpwPageContainer>
  )
}

function AssetDrawerContent({ state }: { state: AssetsWorkbenchProps }) {
  if (state.assetDrawerMode === "create") {
    return (
      <AssetForm
        busy={state.assetActionLoading}
        buttonLabel="Create Asset"
        disabled={state.assetActionLoading || state.projects.length === 0}
        error={state.createError}
        form={state.createForm}
        formLabel="Create Asset form fields"
        onChange={state.setCreateForm}
        onSubmit={state.createAsset}
      />
    )
  }

  if (state.assetDrawerMode === "import") {
    return (
      <AssetContextImportForm
        activeProjectLabel={state.activeProjectLabel}
        assetActionLoading={state.assetActionLoading}
        assetContextFile={state.assetContextFile}
        importAssetContext={state.importAssetContext}
        projectCount={state.projects.length}
        setAssetContextFile={state.setAssetContextFile}
      />
    )
  }

  if (!state.selectedAsset) {
    return (
      <VpwStatusBanner title="No asset selected" tone="warning">
        Select an asset from the inventory before opening this panel.
      </VpwStatusBanner>
    )
  }

  if (state.assetDrawerMode === "edit") {
    return (
      <AssetEditContent
        assetActionLoading={state.assetActionLoading}
        editError={state.editError}
        editForm={state.editForm}
        saveAsset={state.saveAsset}
        setEditForm={state.setEditForm}
      />
    )
  }

  if (state.assetDrawerMode === "linked-findings") {
    return (
      <AssetLinkedFindingsContent
        assetFindings={state.assetFindings}
        assetFindingsError={state.assetFindingsError}
        assetFindingsLoading={state.assetFindingsLoading}
        selectedAsset={state.selectedAsset}
      />
    )
  }

  return (
    <AssetDetailContent
      assetActionLoading={state.assetActionLoading}
      openAssetDrawer={state.openAssetDrawer}
      recalculateAsset={state.recalculateAsset}
      selectedAsset={state.selectedAsset}
      selectedHighestPriority={state.selectedHighestPriority}
    />
  )
}

function assetDrawerTitle(state: AssetsWorkbenchProps) {
  switch (state.assetDrawerMode) {
    case "create":
      return "Add asset"
    case "edit":
      return state.selectedAsset ? `Edit ${state.selectedAsset.name}` : "Edit asset"
    case "import":
      return "Import assets"
    case "linked-findings":
      return state.selectedAsset
        ? `Linked findings for ${state.selectedAsset.name}`
        : "Linked findings"
    case "detail":
      return state.selectedAsset?.name ?? "Asset detail"
    default:
      return "Asset panel"
  }
}

function assetDrawerDescription(state: AssetsWorkbenchProps) {
  switch (state.assetDrawerMode) {
    case "create":
      return "Create one asset context record for the selected project."
    case "edit":
      return "Update ownership, service, exposure, environment and criticality context."
    case "import":
      return "Upload CSV context to update assets for the active project."
    case "linked-findings":
      return "Review findings currently linked to this asset context."
    case "detail":
      return "Inspect identity, metadata and prioritization context for the selected asset."
    default:
      return "Asset context drawer."
  }
}
