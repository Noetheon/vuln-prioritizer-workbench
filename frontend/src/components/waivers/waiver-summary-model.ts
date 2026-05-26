import type { GovernanceWaiverDebtEntryPublic, WaiverPublic } from "@/api-client"
import type { VpwTimelineItem } from "@/components/vpw"
import { statusLabel, statusTone } from "./waiver-lifecycle-model"
import {
  debtScopeLabel,
  formatDate,
  waiverScopeLabel,
} from "./waiver-scope-model"
import type { WaiverDebtSummaryItem, WaiverOwnerRollup } from "./waivers-workbench-model"

export function ownerRollups(waivers: readonly WaiverPublic[]) {
  const rollups = new Map<string, WaiverOwnerRollup>()
  for (const waiver of waivers) {
    const owner = waiver.owner || "Unassigned"
    const current = rollups.get(owner) ?? {
      acceptedFindings: 0,
      active: 0,
      owner,
      reviewDue: 0,
    }
    if (waiver.status !== "expired") {
      current.active += 1
    }
    if (waiver.status === "review_due") {
      current.reviewDue += 1
    }
    current.acceptedFindings += waiver.matched_findings ?? 0
    rollups.set(owner, current)
  }
  return [...rollups.values()].sort(
    (left, right) =>
      right.reviewDue - left.reviewDue ||
      right.acceptedFindings - left.acceptedFindings ||
      left.owner.localeCompare(right.owner),
  )
}

export function summaryValue(
  summary: readonly WaiverDebtSummaryItem[],
  label: string,
  fallback = "0",
) {
  return summary.find((item) => item.label === label)?.value ?? fallback
}

export function isMissingApproval(waiver: WaiverPublic) {
  return !waiver.approval_ref && !waiver.ticket_url
}

export function evidenceCompleteness(waivers: readonly WaiverPublic[]) {
  if (waivers.length === 0) return 0
  const complete = waivers.filter((waiver) => !isMissingApproval(waiver)).length
  return Math.round((complete / waivers.length) * 100)
}

export function reviewQueue(
  debtItems: readonly GovernanceWaiverDebtEntryPublic[],
  waivers: readonly WaiverPublic[],
) {
  if (debtItems.length > 0) {
    return debtItems
      .slice()
      .sort((left, right) => left.days_remaining - right.days_remaining)
      .slice(0, 4)
      .map((item) => ({
        id: item.id,
        owner: item.owner,
        reason: `${statusLabel(item.status)} decision affecting ${item.matched_findings ?? 0} ${item.matched_findings === 1 ? "finding" : "findings"}.`,
        reviewDate: item.review_at
          ? formatDate(item.review_at)
          : formatDate(item.expires_at),
        scope: debtScopeLabel(item),
        status: statusLabel(item.status),
        statusTone: statusTone(item.status),
      }))
  }

  return waivers
    .slice()
    .sort(
      (left, right) =>
        (left.days_remaining ?? 9999) - (right.days_remaining ?? 9999),
    )
    .slice(0, 4)
    .map((waiver) => ({
      id: waiver.id,
      owner: waiver.owner,
      reason: waiver.reason,
      reviewDate: waiver.review_at
        ? formatDate(waiver.review_at)
        : formatDate(waiver.expires_at),
      scope: waiverScopeLabel(waiver),
      status: statusLabel(waiver.status),
      statusTone: statusTone(waiver.status),
    }))
}

export function timelineItems({
  acceptedFindings,
  expired,
  expiringSoon,
  reviewDue,
}: {
  acceptedFindings: string
  expired: string
  expiringSoon: string
  reviewDue: string
}): VpwTimelineItem[] {
  return [
    {
      title: "Created",
      description:
        "Risk acceptance starts only after scope, owner, reason and expiry are recorded.",
      meta: "Required",
      tone: "success",
    },
    {
      title: "Approved",
      description:
        "Approval references or ticket URLs make accepted risk auditable in reports.",
      meta: `${acceptedFindings} accepted ${Number(acceptedFindings) === 1 ? "finding" : "findings"}`,
      tone: "success",
    },
    {
      title: "Review due",
      description:
        "Owner review keeps accepted risk visible before it becomes stale.",
      meta: `${reviewDue} due`,
      tone: Number(reviewDue) > 0 ? "warning" : "neutral",
    },
    {
      title: "Expiring",
      description:
        "Accepted-risk decisions close to expiry should be remediated, renewed, or explicitly re-approved.",
      meta: `${expiringSoon} soon`,
      tone: Number(expiringSoon) > 0 ? "warning" : "neutral",
    },
    {
      title: "Expired",
      description:
        "Expired accepted risk should return to normal remediation pressure.",
      meta: `${expired} expired`,
      tone: Number(expired) > 0 ? "critical" : "neutral",
    },
  ]
}
