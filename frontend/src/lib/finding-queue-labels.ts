import type { FindingPublic } from "@/api-client"

export function findingAssetServiceLabel(finding: FindingPublic) {
  const asset = finding.asset_name?.trim() || finding.asset_key?.trim() || ""
  const service = finding.business_service?.trim() || ""
  if (asset && service) {
    return `${asset} · ${service}`
  }
  return asset || service || "—"
}

export function findingPlannedAction(finding: FindingPublic) {
  const action = finding.recommended_action?.trim().replace(/\.$/, "") ?? ""
  // Provider boilerplate (e.g. CISA KEV required-action text) is too generic
  // for the queue; fall back to a concrete patch instruction per component.
  if (
    action &&
    action.length <= 58 &&
    !action.toLowerCase().startsWith("cisa kev")
  ) {
    return action
  }
  const component = finding.component_name?.trim()
  if (component) {
    const version = finding.component_version?.trim()
    return `Patch ${component}${version ? ` ${version}` : ""}`
  }
  return action || "Review with the asset owner and record the remediation path"
}
