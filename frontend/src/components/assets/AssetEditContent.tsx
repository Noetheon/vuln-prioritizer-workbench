import type { FormEvent } from "react"

import { AssetForm } from "./AssetContextForm"
import type { AssetFormState } from "./asset-model"

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
