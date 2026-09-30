import type {
  AssetPublic,
  FindingPublic,
  GovernanceWaiverDebtEntryPublic,
  WaiverPublic,
} from "@/api-client"
import { shortId } from "@/lib/ui-copy"
import { formatDate as formatWorkbenchDate } from "../../lib/date-format.ts"
import type { WaiverFormStateLike, WaiverMatchPreview } from "./waivers-workbench-model"

export function joinedValues(values: Array<string | null | undefined>) {
  const visible = values.filter(Boolean)
  return visible.length > 0 ? visible.join(" / ") : "Project scope"
}

export { shortId }

export function formatDate(value: string | null | undefined) {
  return formatWorkbenchDate(value, {
    invalidFallback: (invalidValue) => invalidValue,
  })
}

export function waiverScopeLabel(waiver: WaiverPublic) {
  return joinedValues([
    waiver.finding_id ? `Finding ${shortId(waiver.finding_id)}` : null,
    waiver.cve_id ?? null,
    waiver.asset_id ? `Asset ID ${shortId(waiver.asset_id)}` : null,
    waiver.asset_key ?? null,
    waiver.service ?? null,
  ])
}

export function waiverScopeLines(waiver: WaiverPublic) {
  const primary =
    waiver.cve_id ??
    (waiver.finding_id ? `Finding ${shortId(waiver.finding_id)}` : null) ??
    waiver.asset_key ??
    waiver.service ??
    "Project scope"
  const secondary = joinedValues([
    waiver.asset_key && waiver.asset_key !== primary ? waiver.asset_key : null,
    waiver.service && waiver.service !== primary ? waiver.service : null,
    waiver.asset_id ? `Asset ID ${shortId(waiver.asset_id)}` : null,
  ])
  return {
    primary,
    secondary: secondary === "Project scope" ? "" : secondary,
  }
}

export function debtScopeLabel(item: GovernanceWaiverDebtEntryPublic) {
  return joinedValues([
    item.cve_id ?? normalizedDebtScope(item.scope),
    item.asset_key ? `Asset ${item.asset_key}` : null,
    item.service ? `Service ${item.service}` : null,
    item.finding_id ? `Finding ${shortId(item.finding_id)}` : null,
  ])
}

function normalizedDebtScope(scope: string | null | undefined) {
  if (!scope) return null
  const normalized = scope.replace(/^(?:asset|cve|finding|service):/i, "")
  if (!normalized) return null
  if (normalized === "project") return "Project scope"
  return normalized
}

function lower(value: string | null | undefined) {
  return value?.trim().toLowerCase() ?? ""
}

export function matchingFindings(
  form: WaiverFormStateLike,
  findings: readonly FindingPublic[],
) {
  const findingId = lower(form.findingId)
  const cveId = lower(form.cveId)
  const assetId = lower(form.assetId)
  const assetKey = lower(form.assetKey)
  const service = lower(form.service)

  if (!findingId && !cveId && !assetId && !assetKey && !service) {
    return []
  }

  return findings.filter((finding) => {
    if (findingId && lower(finding.id) !== findingId) return false
    if (cveId && lower(finding.cve_id) !== cveId) return false
    if (assetId && lower(finding.asset_id) !== assetId) return false
    if (assetKey && lower(finding.asset_key) !== assetKey) return false
    if (service && lower(finding.business_service) !== service) return false
    return true
  })
}

export function matchPreview(
  form: WaiverFormStateLike,
  findings: readonly FindingPublic[],
  findingsLoading: boolean,
): WaiverMatchPreview {
  if (findingsLoading) {
    return {
      description: "Finding scope is loading from the selected project.",
      findings: [],
      severity: "neutral",
      title: "Scope preview loading",
    }
  }
  const matches = matchingFindings(form, findings)
  const hasScope = [
    form.findingId,
    form.cveId,
    form.assetId,
    form.assetKey,
    form.service,
  ].some((value) => value.trim())
  if (!hasScope) {
    return {
      description: "Add at least one scope anchor to estimate affected findings.",
      findings: [],
      severity: "neutral",
      title: "Scope preview",
    }
  }
  if (matches.length === 0) {
    return {
      description:
        "You can still record this acceptance, but it will not affect current findings until a matching finding exists.",
      findings: matches,
      severity: "warning",
      title: "No matching findings found",
    }
  }
  return {
    description:
      matches.length === 1
        ? "1 finding will be affected."
        : `${matches.length} findings will be affected. Review the affected assets before creating this acceptance.`,
    findings: matches,
    severity: "success",
    title:
      matches.length === 1
        ? "1 finding will be affected"
        : `${matches.length} findings will be affected`,
  }
}

export function findingSummary(finding: FindingPublic) {
  return joinedValues([
    finding.cve_id,
    finding.asset_key ?? finding.asset_name,
    finding.business_service,
  ])
}

export type AcceptableFinding = Pick<
  FindingPublic,
  | "asset_key"
  | "asset_name"
  | "component_name"
  | "component_version"
  | "cve_id"
  | "id"
  | "priority"
>

/** "CVE-2021-44228 · log4j-core 2.14.1 · pay-api-01", for the finding picker. */
export function findingScopeOptionLabel(finding: AcceptableFinding) {
  const component = [finding.component_name, finding.component_version]
    .filter(Boolean)
    .join(" ")
  return [finding.cve_id, component, finding.asset_key ?? finding.asset_name]
    .filter(Boolean)
    .join(" · ")
}

/** Values the project already has, offered while a scope is typed. */
export function scopeSuggestions(
  findings: readonly FindingPublic[],
  assets: readonly AssetPublic[],
) {
  const distinct = (values: Array<string | null | undefined>) =>
    [...new Set(values.filter((value): value is string => Boolean(value)))].sort(
      (left, right) => left.localeCompare(right),
    )
  return {
    assetKeys: distinct([
      ...assets.map((asset) => asset.asset_key),
      ...findings.map((finding) => finding.asset_key),
    ]),
    cveIds: distinct(findings.map((finding) => finding.cve_id)),
    services: distinct([
      ...assets.map((asset) => asset.business_service),
      ...findings.map((finding) => finding.business_service),
    ]),
  }
}
