import type { FindingDetailPublic, FindingPublic } from "@/api-client"
import type { FindingOccurrenceRow } from "@/components/finding-detail/finding-detail-model"
import { stringValue } from "@/lib/app-errors"

export function drawerAssetLabel(finding: FindingPublic | FindingDetailPublic) {
  return (
    finding.asset_name ??
    finding.asset_key ??
    finding.asset_target_ref ??
    "Not supplied"
  )
}

export function cvssText(finding: FindingPublic | FindingDetailPublic) {
  return finding.cvss_base_score !== null &&
    finding.cvss_base_score !== undefined
    ? finding.cvss_base_score.toFixed(1)
    : "Not supplied"
}

export function epssText(finding: FindingPublic | FindingDetailPublic) {
  return finding.epss !== null && finding.epss !== undefined
    ? `${Math.round(finding.epss * 1000) / 10}%`
    : "Not supplied"
}

export function occurrenceAssetLabel(occurrence: FindingOccurrenceRow) {
  return (
    stringValue(occurrence.target_ref) ??
    stringValue(occurrence.raw_reference) ??
    "Affected occurrence"
  )
}

export function occurrenceRowKey(
  occurrence: FindingOccurrenceRow,
  index: number,
) {
  return stringValue(occurrence.id) ?? index
}

export function occurrenceComponentLabel(occurrence: FindingOccurrenceRow) {
  return (
    [
      stringValue(occurrence.component_name),
      stringValue(occurrence.component_version),
    ]
      .filter(Boolean)
      .join(" ") || "Component not supplied"
  )
}

export function occurrenceSourceLabel(occurrence: FindingOccurrenceRow) {
  return (
    stringValue(occurrence.source_format) ??
    stringValue(occurrence.source) ??
    stringValue(occurrence.scanner) ??
    "Source not supplied"
  )
}

export function governanceCopy(finding: FindingPublic | FindingDetailPublic) {
  if (finding.waived) {
    return "Accepted risk is recorded for this finding. Review the acceptance register before changing remediation priority."
  }
  if (finding.suppressed_by_vex) {
    return "A VEX or suppression state is recorded. Validate scope and expiry in the acceptance workflow."
  }
  return "No accepted-risk state is recorded. Use Risk Acceptance only when the organization has approved a time-bound exception."
}
