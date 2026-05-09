import {
  ApiError,
  type AssetCreate,
  type AssetCriticality,
  type AssetEnvironment,
  type AssetExposure,
  type AssetPublic,
  type AssetUpdate,
  type FindingPublic,
} from "../../api-client"
import type { VpwBadgeTone } from "../vpw"
import { formatLabel as labelize } from "../../lib/ui-copy"
import {
  assetFindingsUrlSearch,
  searchStringFromUrlSearch,
} from "../../workbench/selected-project-search"

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

export function apiErrorMessage(prefix: string, caught: unknown) {
  if (caught instanceof ApiError) {
    const detail = apiErrorDetail(caught.body)
    return `${prefix}: ${detail ?? caught.message ?? `HTTP ${caught.status}`}`
  }
  return `${prefix}: unexpected client error`
}

function apiErrorDetail(body: unknown) {
  if (typeof body !== "object" || body === null || !("detail" in body)) {
    return null
  }
  const detail = (body as { detail?: unknown }).detail
  if (typeof detail === "string" && detail.trim()) {
    return detail
  }
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) =>
        typeof item === "object" && item !== null && "msg" in item
          ? String((item as { msg?: unknown }).msg)
          : "",
      )
      .filter(Boolean)
    return messages.length > 0 ? messages.join("; ") : "validation failed"
  }
  if (typeof detail === "object" && detail !== null) {
    const record = detail as Record<string, unknown>
    return typeof record.message === "string" && record.message.trim()
      ? record.message
      : null
  }
  return null
}

export function formatDateTime(value: string | null | undefined) {
  if (!value) {
    return "N.A."
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return "N.A."
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date)
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

function cleanOptional(value: string) {
  const trimmed = value.trim()
  return trimmed ? trimmed : null
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

export function assetUpdateBody(form: AssetFormState): AssetUpdate {
  return assetRequestBody(form)
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

export function matchesAsset(finding: FindingPublic, asset: AssetPublic) {
  return (
    finding.asset_id === asset.id ||
    finding.asset_key === asset.asset_key ||
    finding.asset_name === asset.name
  )
}

export function findingAssetLabel(finding: FindingPublic) {
  return (
    finding.asset_name ??
    finding.asset_key ??
    finding.business_service ??
    "N.A."
  )
}

export function assetFindingsHref(asset: AssetPublic) {
  const search = searchStringFromUrlSearch(
    assetFindingsUrlSearch({
      assetId: asset.id,
      assetKey: asset.asset_key,
      projectId: asset.project_id,
    }),
  )
  return `/findings?${search}`
}

export function criticalityTone(
  value: AssetCriticality | string | null | undefined,
): VpwBadgeTone {
  switch (String(value ?? "").toLowerCase()) {
    case "critical":
      return "critical"
    case "high":
      return "warning"
    case "medium":
      return "info"
    case "low":
      return "success"
    default:
      return "neutral"
  }
}

export function exposureTone(
  value: AssetExposure | string | null | undefined,
): VpwBadgeTone {
  switch (String(value ?? "").toLowerCase()) {
    case "internet-facing":
      return "warning"
    case "internal":
      return "info"
    case "private":
      return "success"
    default:
      return "neutral"
  }
}

export function environmentTone(
  value: AssetEnvironment | string | null | undefined,
): VpwBadgeTone {
  switch (String(value ?? "").toLowerCase()) {
    case "production":
      return "warning"
    case "staging":
    case "test":
      return "info"
    case "development":
      return "support"
    default:
      return "neutral"
  }
}

export function findingPriorityTone(
  value: string | null | undefined,
): VpwBadgeTone {
  switch (String(value ?? "").toLowerCase()) {
    case "critical":
      return "critical"
    case "high":
      return "warning"
    case "medium":
      return "info"
    case "low":
      return "success"
    default:
      return "neutral"
  }
}

export function findingStatusTone(value: string | null | undefined): VpwBadgeTone {
  switch (String(value ?? "").toLowerCase()) {
    case "resolved":
    case "accepted":
    case "false_positive":
      return "success"
    case "in_progress":
    case "triaged":
      return "info"
    case "deferred":
      return "warning"
    default:
      return "neutral"
  }
}

export function assetScoreTone(asset: AssetPublic): VpwBadgeTone {
  return asset.rescore_needed ? "warning" : "success"
}

export function scoreStatusLabel(asset: AssetPublic) {
  return asset.rescore_needed ? "Re-score needed" : "Current"
}

export function highestFindingPriority(findings: readonly FindingPublic[]) {
  const order = ["critical", "high", "medium", "low"]
  const priorities = findings
    .map((finding) => String(finding.priority ?? "").toLowerCase())
    .filter(Boolean)
  const highest = order.find((priority) => priorities.includes(priority))
  return highest ? labelize(highest) : "N.A."
}

export type AssetSummary = {
  criticalServices: number
  internetFacing: number
  linkedFindings: number
  ownerCoverage: number
  production: number
  total: number
}

export function summarizeAssets(assets: readonly AssetPublic[]): AssetSummary {
  const total = assets.length
  const ownerCount = assets.filter((asset) => asset.owner?.trim()).length
  const criticalServices = new Set(
    assets
      .filter((asset) =>
        ["critical", "high"].includes(String(asset.criticality ?? "")),
      )
      .map((asset) => asset.business_service || asset.name || asset.asset_key),
  ).size

  return {
    criticalServices,
    internetFacing: assets.filter(
      (asset) => asset.exposure === "internet-facing",
    ).length,
    linkedFindings: assets.reduce(
      (totalFindings, asset) => totalFindings + (asset.finding_count ?? 0),
      0,
    ),
    ownerCoverage: total > 0 ? Math.round((ownerCount / total) * 100) : 0,
    production: assets.filter((asset) => asset.environment === "production")
      .length,
    total,
  }
}

export type ServiceRollup = {
  assetCount: number
  criticalAssets: number
  exposure: string
  findings: number
  id: string
  label: string
  owner: string
}

export function buildServiceRollups(
  assets: readonly AssetPublic[],
): ServiceRollup[] {
  const rollups = new Map<string, ServiceRollup>()

  for (const asset of assets) {
    const label = asset.business_service || "Unassigned service"
    const existing = rollups.get(label) ?? {
      assetCount: 0,
      criticalAssets: 0,
      exposure: "unknown",
      findings: 0,
      id: label,
      label,
      owner: "N.A.",
    }

    existing.assetCount += 1
    existing.findings += asset.finding_count ?? 0
    if (["critical", "high"].includes(String(asset.criticality ?? ""))) {
      existing.criticalAssets += 1
    }
    if (asset.owner && existing.owner === "N.A.") {
      existing.owner = asset.owner
    }
    if (asset.exposure === "internet-facing") {
      existing.exposure = "internet-facing"
    } else if (
      existing.exposure === "unknown" &&
      asset.exposure &&
      asset.exposure !== "unknown"
    ) {
      existing.exposure = asset.exposure
    }

    rollups.set(label, existing)
  }

  return [...rollups.values()].sort((left, right) => {
    const riskDelta = right.criticalAssets - left.criticalAssets
    return riskDelta !== 0 ? riskDelta : right.findings - left.findings
  })
}
