import {
  isMissingApproval,
  type WaiversWorkbenchProps,
  waiverScopeLabel,
} from "./waivers-workbench-model"

export const waiverViews = [
  { label: "All", value: "all" },
  { label: "Active", value: "active" },
  { label: "Needs review", value: "needs-review" },
  { label: "Expiring", value: "expiring" },
  { label: "Expired", value: "expired" },
] as const

export const waiverEvidenceViews = [
  { label: "All", value: "all" },
  { label: "Incomplete", value: "missing" },
  { label: "Complete", value: "recorded" },
] as const

export const waiverFindingViews = [
  { label: "All", value: "all" },
  { label: "Matched", value: "matched" },
  { label: "None", value: "none" },
] as const

export const waiverScopeTypeViews = [
  { label: "All", value: "all" },
  { label: "CVE", value: "cve" },
  { label: "Asset", value: "asset" },
  { label: "Service", value: "service" },
  { label: "Finding", value: "finding" },
  { label: "Project", value: "project" },
] as const

export function matchesWaiverEvidenceView(
  waiver: WaiversWorkbenchProps["waivers"][number],
  view: string,
) {
  if (view === "missing") return isMissingApproval(waiver)
  if (view === "recorded") return !isMissingApproval(waiver)
  return true
}

export function matchesWaiverView(
  waiver: WaiversWorkbenchProps["waivers"][number],
  view: string,
) {
  if (view === "all") return true
  if (view === "active") return waiver.status === "active"
  if (view === "expired") return waiver.status === "expired"
  if (view === "needs-review") return waiver.status === "review_due"
  if (view === "expiring") {
    return (
      waiver.status !== "expired" &&
      waiver.days_remaining !== null &&
      waiver.days_remaining !== undefined &&
      waiver.days_remaining >= 0 &&
      waiver.days_remaining <= 30
    )
  }
  return true
}

export function matchesWaiverFindingView(
  waiver: WaiversWorkbenchProps["waivers"][number],
  view: string,
) {
  const matchedFindings = waiver.matched_findings ?? 0
  if (view === "matched") return matchedFindings > 0
  if (view === "none") return matchedFindings === 0
  return true
}

export function matchesWaiverOwnerView(
  waiver: WaiversWorkbenchProps["waivers"][number],
  owner: string,
) {
  if (owner === "all") return true
  return waiver.owner === owner
}

export function matchesWaiverScopeTypeView(
  waiver: WaiversWorkbenchProps["waivers"][number],
  view: string,
) {
  if (view === "all") return true
  if (view === "cve") return Boolean(waiver.cve_id)
  if (view === "asset") return Boolean(waiver.asset_id || waiver.asset_key)
  if (view === "service") return Boolean(waiver.service)
  if (view === "finding") return Boolean(waiver.finding_id)
  if (view === "project") {
    return ![
      waiver.cve_id,
      waiver.asset_id,
      waiver.asset_key,
      waiver.service,
      waiver.finding_id,
    ].some(Boolean)
  }
  return true
}

export function matchesWaiverSearch(
  waiver: WaiversWorkbenchProps["waivers"][number],
  search: string,
) {
  const term = search.trim().toLowerCase()
  if (!term) return true
  return [
    waiverScopeLabel(waiver),
    waiver.owner,
    waiver.reason,
    waiver.status,
    waiver.approval_ref,
    waiver.ticket_url,
  ]
    .filter(Boolean)
    .some((value) => String(value).toLowerCase().includes(term))
}
