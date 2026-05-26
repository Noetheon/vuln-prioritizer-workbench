import type { WaiverPublic } from "@/api-client"
import type { VpwBadgeTone } from "@/components/vpw"
import { formatLabel as labelize } from "@/lib/ui-copy"

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
