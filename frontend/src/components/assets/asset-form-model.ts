import type {
  AssetCreate,
  AssetCriticality,
  AssetEnvironment,
  AssetExposure,
  AssetPublic,
  AssetUpdate,
} from "../../api-client"

export const criticalityOptions: AssetCriticality[] = [
  "critical",
  "high",
  "medium",
  "low",
  "unknown",
]

export const environmentOptions: AssetEnvironment[] = [
  "production",
  "staging",
  "development",
  "test",
  "unknown",
]

export const exposureOptions: AssetExposure[] = [
  "internet-facing",
  "internal",
  "private",
  "unknown",
]

export type AssetFormState = {
  asset_key: string
  business_service: string
  criticality: AssetCriticality
  environment: AssetEnvironment
  exposure: AssetExposure
  name: string
  owner: string
  target_ref: string
}

export const emptyAssetForm: AssetFormState = {
  asset_key: "",
  business_service: "",
  criticality: "unknown",
  environment: "unknown",
  exposure: "unknown",
  name: "",
  owner: "",
  target_ref: "",
}

export function assetFormFromAsset(asset: AssetPublic): AssetFormState {
  return {
    asset_key: asset.asset_key,
    business_service: asset.business_service ?? "",
    criticality: asset.criticality ?? "unknown",
    environment: asset.environment ?? "unknown",
    exposure: asset.exposure ?? "unknown",
    name: asset.name,
    owner: asset.owner ?? "",
    target_ref: asset.target_ref ?? "",
  }
}

export function assetRequestBody(form: AssetFormState): AssetCreate {
  return {
    asset_key: form.asset_key.trim(),
    business_service: cleanOptional(form.business_service),
    criticality: form.criticality,
    environment: form.environment,
    exposure: form.exposure,
    name: form.name.trim(),
    owner: cleanOptional(form.owner),
    target_ref: cleanOptional(form.target_ref),
  }
}

export function assetUpdateBody(
  form: AssetFormState,
  currentAssetKey?: string,
): AssetUpdate {
  const body: AssetUpdate = assetRequestBody(form)
  if (currentAssetKey && body.asset_key === currentAssetKey.trim()) {
    delete body.asset_key
  }
  return body
}

export function validateAssetForm(form: AssetFormState) {
  if (!form.asset_key.trim()) {
    return "Asset key is required."
  }
  if (!form.name.trim()) {
    return "Asset name is required."
  }
  if (!criticalityOptions.includes(form.criticality)) {
    return "Criticality must be a supported value."
  }
  if (!environmentOptions.includes(form.environment)) {
    return "Environment must be a supported value."
  }
  if (!exposureOptions.includes(form.exposure)) {
    return "Exposure must be a supported value."
  }
  return ""
}

function cleanOptional(value: string) {
  const trimmed = value.trim()
  return trimmed ? trimmed : null
}
