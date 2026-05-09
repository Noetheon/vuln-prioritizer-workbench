import type { FormEventHandler } from "react"
import type {
  GovernanceWaiverDebtEntryPublic,
  ProjectDecisionSummaryPublic,
  ProjectPublic,
  WaiverPublic,
} from "@/api-client"
import type { VpwBadgeTone, VpwTimelineItem } from "@/components/vpw"
import { formatLabel as labelize } from "@/lib/ui-copy"

export type WaiverFormStateLike = {
  approvalRef: string
  assetId: string
  assetKey: string
  cveId: string
  expiresAt: string
  findingId: string
  owner: string
  reason: string
  reviewAt: string
  service: string
  ticketUrl: string
}

export type WaiverDebtSummaryItem = {
  detail: string
  label: string
  value: string
}

export type WaiversWorkbenchProps = {
  projectListLoading: boolean
  projectSummary: ProjectDecisionSummaryPublic | null
  projects: ProjectPublic[]
  selectedProject: ProjectPublic | null
  selectedProjectId: string
  onCreateWaiver: FormEventHandler<HTMLFormElement>
  onExpireWaiver: (waiver: WaiverPublic) => void
  onFieldChange: (field: keyof WaiverFormStateLike, value: string) => void
  onProjectChange: (projectId: string) => void
  onRefreshWaivers: () => void
  waiverActionError: string
  waiverActionLoading: boolean
  waiverActionMessage: string
  waiverDebtItems: readonly GovernanceWaiverDebtEntryPublic[]
  waiverDebtSummary: readonly WaiverDebtSummaryItem[]
  waiverForm: WaiverFormStateLike
  waivers: WaiverPublic[]
  waiversError: string
  waiversLoading: boolean
}

export function joinedValues(values: Array<string | null | undefined>) {
  const visible = values.filter(Boolean)
  return visible.length > 0 ? visible.join(" / ") : "Project scope"
}

export function shortId(value: string | null | undefined) {
  return value ? value.slice(0, 8) : "N.A."
}

export function formatDate(value: string | null | undefined) {
  if (!value) return "N.A."
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
  }).format(date)
}

export function waiverScopeLabel(waiver: WaiverPublic) {
  return joinedValues([
    waiver.finding_id ? `Finding ${shortId(waiver.finding_id)}` : null,
    waiver.cve_id ? `CVE ${waiver.cve_id}` : null,
    waiver.asset_id ? `Asset ID ${shortId(waiver.asset_id)}` : null,
    waiver.asset_key ? `Asset ${waiver.asset_key}` : null,
    waiver.service ? `Service ${waiver.service}` : null,
  ])
}

export function debtScopeLabel(item: GovernanceWaiverDebtEntryPublic) {
  return joinedValues([
    item.scope,
    item.cve_id ? `CVE ${item.cve_id}` : null,
    item.asset_key ? `Asset ${item.asset_key}` : null,
    item.service ? `Service ${item.service}` : null,
    item.finding_id ? `Finding ${shortId(item.finding_id)}` : null,
  ])
}

export function statusTone(status: string | null | undefined): VpwBadgeTone {
  switch (status) {
    case "active":
      return "success"
    case "review_due":
      return "warning"
    case "expired":
      return "critical"
    default:
      return "neutral"
  }
}

export function statusLabel(status: string | null | undefined) {
  return labelize(status ?? "unknown")
}

export function daysLabel(days: number | null | undefined) {
  if (days === null || days === undefined) return "No lifecycle data"
  if (days < 0) return `${Math.abs(days)} day(s) overdue`
  if (days === 0) return "Due today"
  return `${days} day(s) remaining`
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
        reason: `${statusLabel(item.status)} waiver affecting ${item.matched_findings ?? 0} finding(s).`,
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
      meta: `${acceptedFindings} accepted finding(s)`,
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
        "Waivers close to expiry should be remediated, renewed, or explicitly re-approved.",
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
