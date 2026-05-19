import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "../ui/sheet"
import { VpwStatusBanner } from "../vpw"
import { AssetContextImportForm, AssetForm } from "./AssetContextForm"
import {
  AssetDetailContent,
  AssetEditContent,
  AssetLinkedFindingsContent,
} from "./AssetLinkedFindingsPanel"
import type { AssetsWorkbenchProps } from "./AssetsRoute"

type AssetDrawerProps = {
  state: AssetsWorkbenchProps
}

export function AssetDrawer({ state }: AssetDrawerProps) {
  const drawerTitle = assetDrawerTitle(state)
  const drawerDescription = assetDrawerDescription(state)

  return (
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
  )
}

function AssetDrawerContent({ state }: AssetDrawerProps) {
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
      return state.selectedAsset
        ? `Edit ${state.selectedAsset.name}`
        : "Edit asset"
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
