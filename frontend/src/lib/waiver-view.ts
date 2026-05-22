import type {
  FindingDetailPublic,
  WaiverCreate,
  WaiverPublic,
} from "../api-client"
import { joinedValues, objectRecord, stringValue } from "./app-errors"

export type WaiverFormState = {
  findingId: string
  cveId: string
  assetId: string
  assetKey: string
  service: string
  owner: string
  reason: string
  expiresAt: string
  reviewAt: string
  approvalRef: string
  ticketUrl: string
}

export type FindingWaiverEvidence = {
  approvalRef: string | null
  daysRemaining: string | null
  expiresOn: string | null
  id: string | null
  matchedScope: string | null
  owner: string | null
  reason: string | null
  reviewOn: string | null
  scope: string | null
  status: string | null
  ticketUrl: string | null
}

export const emptyWaiverForm: WaiverFormState = {
  approvalRef: "",
  assetId: "",
  assetKey: "",
  cveId: "",
  expiresAt: "",
  findingId: "",
  owner: "",
  reason: "",
  reviewAt: "",
  service: "",
  ticketUrl: "",
}

function dateValueFromOffset(days: number) {
  const date = new Date()
  date.setDate(date.getDate() + days)
  return date.toISOString().slice(0, 10)
}

export function waiverFormDefaults(): WaiverFormState {
  return {
    ...emptyWaiverForm,
    expiresAt: dateValueFromOffset(30),
    reviewAt: dateValueFromOffset(14),
  }
}

function nullableTrimmed(value: string) {
  const trimmed = value.trim()
  return trimmed ? trimmed : null
}

export function validateWaiverForm(form: WaiverFormState) {
  if (
    !form.findingId.trim() &&
    !form.cveId.trim() &&
    !form.assetId.trim() &&
    !form.assetKey.trim() &&
    !form.service.trim()
  ) {
    return "At least one acceptance scope is required."
  }
  if (!form.owner.trim()) {
    return "Owner is required."
  }
  if (!form.reason.trim()) {
    return "Reason is required."
  }
  if (!form.expiresAt.trim()) {
    return "Expiry date is required."
  }
  if (form.reviewAt.trim()) {
    const review = new Date(form.reviewAt)
    const expiry = new Date(form.expiresAt)
    if (
      !Number.isNaN(review.getTime()) &&
      !Number.isNaN(expiry.getTime()) &&
      review > expiry
    ) {
      return "Review date must be before or on the expiry date."
    }
  }
  return ""
}

export function waiverRequestBody(form: WaiverFormState): WaiverCreate {
  return {
    approval_ref: nullableTrimmed(form.approvalRef),
    asset_id: nullableTrimmed(form.assetId),
    asset_key: nullableTrimmed(form.assetKey),
    cve_id: nullableTrimmed(form.cveId),
    expires_at: nullableTrimmed(form.expiresAt),
    finding_id: nullableTrimmed(form.findingId),
    owner: nullableTrimmed(form.owner),
    reason: nullableTrimmed(form.reason),
    review_at: nullableTrimmed(form.reviewAt),
    service: nullableTrimmed(form.service),
    ticket_url: nullableTrimmed(form.ticketUrl),
  }
}

export function waiverFormFromWaiver(waiver: WaiverPublic): WaiverFormState {
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

export function waiverScopeLabel(waiver: WaiverPublic) {
  return joinedValues([
    waiver.finding_id ? `Finding ${waiver.finding_id.slice(0, 8)}` : null,
    waiver.cve_id ?? null,
    waiver.asset_id ? `Asset ID ${waiver.asset_id}` : null,
    waiver.asset_key ?? null,
    waiver.service ?? null,
  ])
}

export function findingWaiverEvidence(
  finding: FindingDetailPublic | null,
): FindingWaiverEvidence | null {
  if (!finding?.waived) {
    return null
  }
  const explanation = objectRecord(finding.explanation_json)
  const evidence = objectRecord(finding.evidence_json)
  const nested = {
    ...objectRecord(evidence.waiver),
    ...objectRecord(explanation.waiver),
  }
  const record = {
    ...evidence,
    ...explanation,
    ...nested,
  }
  const status = stringValue(record.waiver_status)
  const id = stringValue(record.waiver_id)
  const reason = stringValue(record.waiver_reason)
  const owner = stringValue(record.waiver_owner)
  const expiresOn = stringValue(record.waiver_expires_on)
  const reviewOn = stringValue(record.waiver_review_on)
  const scope = stringValue(record.waiver_scope)
  const matchedScope = stringValue(record.waiver_matched_scope)
  const approvalRef = stringValue(record.waiver_approval_ref)
  const ticketUrl = stringValue(record.waiver_ticket_url)
  const daysRemaining =
    typeof record.waiver_days_remaining === "number"
      ? String(record.waiver_days_remaining)
      : stringValue(record.waiver_days_remaining)
  if (
    !id &&
    !status &&
    !reason &&
    !owner &&
    !expiresOn &&
    !scope &&
    !approvalRef &&
    !ticketUrl
  ) {
    return null
  }
  return {
    approvalRef,
    daysRemaining,
    expiresOn,
    id,
    matchedScope,
    owner,
    reason,
    reviewOn,
    scope,
    status,
    ticketUrl,
  }
}
