import type { WaiverPublic } from "@/api-client"
import type { WaiverFormStateLike } from "./waivers-workbench-model"

export function timeboxWarning(form: WaiverFormStateLike) {
  if (!form.expiresAt) return ""
  const expiry = new Date(form.expiresAt)
  const today = new Date()
  today.setHours(0, 0, 0, 0)
  if (Number.isNaN(expiry.getTime())) {
    return ""
  }
  if (expiry < today) {
    return "Expiry date is in the past. This decision should be time-boxed into the future."
  }
  if (form.reviewAt) {
    const review = new Date(form.reviewAt)
    if (!Number.isNaN(review.getTime()) && review > expiry) {
      return "Review date should be before or on the expiry date."
    }
  }
  const days = Math.ceil((expiry.getTime() - today.getTime()) / 86400000)
  if (days > 180) {
    return "Expiry is more than 180 days away. Record a strong rationale for this long acceptance window."
  }
  if (days > 90) {
    return "Expiry is more than 90 days away. Review whether the acceptance window is too broad."
  }
  return ""
}

export function evidenceFormComplete(form: WaiverFormStateLike) {
  return Boolean(form.approvalRef.trim() || form.ticketUrl.trim())
}

export function scopeAnchorWarning(form: WaiverFormStateLike) {
  const hasFindingOrAssetOrService = [
    form.findingId,
    form.assetId,
    form.assetKey,
    form.service,
  ].some((value) => value.trim())
  if (form.cveId.trim() && !hasFindingOrAssetOrService) {
    return "CVE-only acceptance can affect every matching asset. Add a finding, asset, or service when the decision is narrower."
  }
  return ""
}

export function waiverFormFromRecord(waiver: WaiverPublic): WaiverFormStateLike {
  return {
    approvalRef: waiver.approval_ref ?? "",
    assetId: waiver.asset_id ?? "",
    assetKey: waiver.asset_key ?? "",
    cveId: waiver.cve_id ?? "",
    expiresAt: waiver.expires_at?.slice(0, 10) ?? "",
    findingId: waiver.finding_id ?? "",
    owner: waiver.owner,
    reason: waiver.reason,
    reviewAt: waiver.review_at?.slice(0, 10) ?? "",
    service: waiver.service ?? "",
    ticketUrl: waiver.ticket_url ?? "",
  }
}
