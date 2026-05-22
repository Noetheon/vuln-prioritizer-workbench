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
