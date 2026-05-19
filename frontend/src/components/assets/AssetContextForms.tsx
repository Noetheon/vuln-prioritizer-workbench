import type { FormEvent } from "react"
import { VpwGrid, VpwPanel, VpwSectionHeader } from "../vpw"
import { AssetContextImportForm } from "./AssetContextImportForm"
import { AssetForm } from "./AssetForm"
import type { AssetFormState } from "./asset-model"

export function AssetContextForms({
  activeProjectLabel,
  assetActionLoading,
  assetContextFile,
  createAsset,
  createError,
  createForm,
  importAssetContext,
  projectCount,
  setAssetContextFile,
  setCreateForm,
}: {
  activeProjectLabel: string
  assetActionLoading: boolean
  assetContextFile: File | null
  createAsset: (event: FormEvent<HTMLFormElement>) => void
  createError: string
  createForm: AssetFormState
  importAssetContext: (event: FormEvent<HTMLFormElement>) => void
  projectCount: number
  setAssetContextFile: (file: File | null) => void
  setCreateForm: (form: AssetFormState) => void
}) {
  return (
    <VpwGrid columns={2}>
      <div id="asset-context-import">
        <AssetContextImportPanel
          activeProjectLabel={activeProjectLabel}
          assetActionLoading={assetActionLoading}
          assetContextFile={assetContextFile}
          importAssetContext={importAssetContext}
          projectCount={projectCount}
          setAssetContextFile={setAssetContextFile}
        />
      </div>

      <VpwPanel className="flex flex-col gap-4 p-5">
        <VpwSectionHeader
          description="Create a single asset context record when a CSV import is not needed."
          eyebrow="Manual context"
          title="Create asset"
        />
        <AssetForm
          busy={assetActionLoading}
          buttonLabel="Create Asset"
          disabled={assetActionLoading || projectCount === 0}
          error={createError}
          form={createForm}
          formLabel="Create Asset form fields"
          onChange={setCreateForm}
          onSubmit={createAsset}
        />
      </VpwPanel>
    </VpwGrid>
  )
}

function AssetContextImportPanel(
  props: Parameters<typeof AssetContextImportForm>[0],
) {
  return (
    <VpwPanel className="flex flex-col gap-4 p-5">
      <VpwSectionHeader
        description="Upload CSV context to update asset ownership, service, environment, exposure and criticality."
        eyebrow="Context intake"
        title="Import asset context"
      />
      <AssetContextImportForm {...props} />
    </VpwPanel>
  )
}
