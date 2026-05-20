import type { FindingDetailPublic, FindingExplanationPublic } from "@/api-client"
import { joinedValues, objectRecord, stringValue } from "@/lib/app-errors"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"
import type { FindingWaiverEvidence } from "@/lib/waiver-view"
import type {
  FindingDetailRow,
  FindingOccurrenceRow,
} from "./finding-detail-shared"
import type { findingDataQualityRows } from "./finding-detail-occurrence-model"

export function findingEvidenceRows(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
  occurrences: readonly FindingOccurrenceRow[],
  dataQualityRows: ReturnType<typeof findingDataQualityRows>,
  providerGaps: readonly string[],
): FindingDetailRow[] {
  const firstOccurrence = occurrences[0]
  const providerEvidence = objectRecord(
    explanation?.provider_evidence ??
      objectRecord(finding?.explanation_json).provider_evidence,
  )
  const evidence = objectRecord(finding?.evidence_json)
  const providerSignalLabels = [
    finding?.epss !== null && finding?.epss !== undefined ? "EPSS" : null,
    finding?.cvss_base_score !== null && finding?.cvss_base_score !== undefined
      ? "CVSS"
      : null,
    finding?.in_kev ? "CISA KEV" : null,
  ].filter((label): label is string => Boolean(label))
  const providerKeys = Object.keys(providerEvidence)
  const artifactRef =
    stringValue(evidence.report_artifact) ??
    stringValue(evidence.report_reference) ??
    stringValue(evidence.artifact_reference) ??
    stringValue(firstOccurrence?.vex_source_path)
  const dataQualityLabels = Array.from(
    new Set(dataQualityRows.map((row) => labelize(row.code))),
  )

  return [
    {
      detail:
        providerGaps.length > 0
          ? `Gaps: ${providerGaps.join(", ")}`
          : "No provider gaps recorded for the stored finding signals.",
      label: "Provider snapshot",
      value:
        providerKeys.length > 0
          ? `${providerKeys.length} provider evidence field(s) recorded`
          : providerSignalLabels.length > 0
            ? providerSignalLabels.join(", ")
            : "No provider snapshot recorded",
    },
    {
      detail: optionalText(
        stringValue(firstOccurrence?.source_record_id) ??
          stringValue(firstOccurrence?.raw_reference) ??
          stringValue(firstOccurrence?.source_id),
      ),
      label: "Input source",
      value: optionalText(
        stringValue(firstOccurrence?.source_format) ??
          stringValue(firstOccurrence?.source) ??
          stringValue(evidence.input_source),
      ),
    },
    {
      detail: optionalText(stringValue(firstOccurrence?.raw_severity)),
      label: "Scanner evidence",
      value: optionalText(
        stringValue(firstOccurrence?.scanner) ??
          stringValue(evidence.scanner) ??
          stringValue(evidence.tool),
      ),
    },
    {
      detail:
        dataQualityRows.length > 0
          ? dataQualityLabels.join(", ")
          : "No data quality flags recorded.",
      label: "Data quality notes",
      value:
        explanation?.data_quality_confidence ??
        stringValue(objectRecord(finding?.data_quality_json).confidence) ??
        "Recorded",
    },
    {
      detail:
        "Report or evidence bundle reference when supplied by input data.",
      label: "Report / artifact references",
      value: optionalText(artifactRef),
    },
  ]
}

function formatFindingDateTime(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date)
}

export function findingHistoryRows(
  finding: FindingDetailPublic | null,
  occurrences: readonly FindingOccurrenceRow[],
  waiverEvidence: FindingWaiverEvidence | null,
): FindingDetailRow[] {
  const vexStatus =
    occurrences
      .map((occurrence) => stringValue(occurrence.vex_status))
      .find(Boolean) ?? null
  const vexDetail =
    occurrences
      .map((occurrence) =>
        joinedValues([
          stringValue(occurrence.vex_justification),
          stringValue(occurrence.vex_action_statement),
          stringValue(occurrence.vex_match_type),
        ]),
      )
      .find((value) => value !== "Not supplied") ?? null

  return [
    {
      detail: "Initial source occurrence recorded by Workbench.",
      label: "First seen",
      value: finding?.first_seen_at
        ? formatFindingDateTime(finding.first_seen_at)
        : "Not recorded",
    },
    {
      detail: "Most recent source occurrence recorded by Workbench.",
      label: "Last seen",
      value: finding?.last_seen_at
        ? formatFindingDateTime(finding.last_seen_at)
        : "Not recorded",
    },
    {
      detail: finding?.updated_at
        ? `Last updated ${formatFindingDateTime(finding.updated_at)}`
        : "No status update timestamp recorded.",
      label: "Status changes",
      value: labelize(finding?.status),
    },
    {
      detail:
        waiverEvidence?.reason ??
        vexDetail ??
        "No waiver or VEX state recorded for this finding.",
      label: "Waiver / VEX state",
      value: finding?.waived
        ? `Waived${waiverEvidence?.status ? ` (${labelize(waiverEvidence.status)})` : ""}`
        : finding?.suppressed_by_vex
          ? "Suppressed by VEX"
          : vexStatus
            ? labelize(vexStatus)
            : "Not accepted",
    },
  ]
}
