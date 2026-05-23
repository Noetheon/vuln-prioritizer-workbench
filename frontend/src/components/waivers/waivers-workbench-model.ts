import type { FormEventHandler } from "react"
import type {
  FindingPublic,
  GovernanceWaiverDebtEntryPublic,
  ProjectDecisionSummaryPublic,
  ProjectPublic,
  WaiverPublic,
} from "@/api-client"
import type { VpwBadgeTone, VpwTimelineItem } from "@/components/vpw"
import { formatLabel as labelize, shortId } from "@/lib/ui-copy"
import { formatDate as formatWorkbenchDate } from "../../lib/date-format.ts"

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

export type WaiverDrawerMode = "detail" | "create" | "review" | "expire" | null

export type WaiversWorkbenchProps = {
  projectListLoading: boolean
  projectSummary: ProjectDecisionSummaryPublic | null
  projects: ProjectPublic[]
  selectedProject: ProjectPublic | null
  selectedProjectId: string
  closeWaiverDrawer: () => void
  findings: FindingPublic[]
  findingsError: string
  findingsLoading: boolean
  onCreateWaiver: FormEventHandler<HTMLFormElement>
  onExpireWaiver: (waiver: WaiverPublic) => void
  onFieldChange: (field: keyof WaiverFormStateLike, value: string) => void
  onProjectChange: (projectId: string) => void
  onRefreshWaivers: () => void
  onReviewFieldChange: (field: keyof WaiverFormStateLike, value: string) => void
  onUpdateWaiver: FormEventHandler<HTMLFormElement>
  openWaiverDrawer: (mode: Exclude<WaiverDrawerMode, null>, waiver?: WaiverPublic) => void
  selectedWaiver: WaiverPublic | null
  selectedWaiverId: string
  waiverActionError: string
  waiverActionLoading: boolean
  waiverActionMessage: string
  waiverDebtItems: readonly GovernanceWaiverDebtEntryPublic[]
  waiverDebtSummary: readonly WaiverDebtSummaryItem[]
  waiverDrawerMode: WaiverDrawerMode
  waiverEditForm: WaiverFormStateLike
  waiverForm: WaiverFormStateLike
  waivers: WaiverPublic[]
  waiversError: string
  waiversLoading: boolean
}

export type WaiverMatchPreview = {
  description: string
  findings: FindingPublic[]
  severity: "neutral" | "success" | "warning"
  title: string
}

export type WaiverOwnerRollup = {
  acceptedFindings: number
  active: number
  owner: string
  reviewDue: number
}

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
  if (days < 0) {
    const overdue = Math.abs(days)
    return `${overdue} day${overdue === 1 ? "" : "s"} overdue`
  }
  if (days === 0) return "Due today"
  return `${days} day${days === 1 ? "" : "s"} remaining`
}

export function lifecycleLabel(waiver: WaiverPublic) {
  if (waiver.status === "expired") return "Expired"
  if (waiver.status === "review_due") return "Review due"
  const daysRemaining = waiver.days_remaining
  if (
    daysRemaining !== null &&
    daysRemaining !== undefined &&
    daysRemaining >= 0 &&
    daysRemaining <= 30
  ) {
    return "Expiring soon"
  }
  return "Active"
}

export function lifecycleStatusToken(waiver: WaiverPublic) {
  const label = lifecycleLabel(waiver)
  if (label === "Expired") return "failed"
  if (label === "Review due" || label === "Expiring soon") return "review_due"
  return "active"
}

export function evidenceStateLabel(
  waiver: Pick<WaiverPublic, "approval_ref" | "ticket_url">,
) {
  return waiver.approval_ref || waiver.ticket_url ? "Complete" : "Incomplete"
}

export function evidenceStateToken(
  waiver: Pick<WaiverPublic, "approval_ref" | "ticket_url">,
) {
  return waiver.approval_ref || waiver.ticket_url ? "ready" : "review_due"
}

export function evidenceDetail(
  waiver: Pick<WaiverPublic, "approval_ref" | "ticket_url">,
) {
  return waiver.approval_ref ?? waiver.ticket_url ?? "No approval reference or ticket"
}

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

export function findingSummary(finding: FindingPublic) {
  return joinedValues([
    finding.cve_id,
    finding.asset_key ?? finding.asset_name,
    finding.business_service,
  ])
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
