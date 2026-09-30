import type { FindingPublic, FindingStatus } from "@/api-client"

// Open work: what the remediation queue may suggest as a next action.
const ACTIONABLE_FINDING_STATUSES: ReadonlySet<FindingStatus> = new Set([
  "open",
  "in_review",
  "remediating",
])

export function isActionableFinding(finding: FindingPublic) {
  // The API defaults a missing status to open.
  return ACTIONABLE_FINDING_STATUSES.has(finding.status ?? "open")
}

// Queue order for the Overview: open findings only, highest score first.
export function rankedRemediationQueue(
  findings: readonly FindingPublic[],
  queueSearch: string,
) {
  const query = queueSearch.trim().toLowerCase()
  return findings
    .filter(isActionableFinding)
    .sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0))
    .filter((finding) => {
      if (!query) return true
      const fields = [
        finding.cve_id,
        finding.owner,
        finding.business_service,
        finding.component_name,
        finding.rationale,
        finding.recommended_action,
      ]
      return fields.some((field) => field?.toLowerCase().includes(query))
    })
}

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
