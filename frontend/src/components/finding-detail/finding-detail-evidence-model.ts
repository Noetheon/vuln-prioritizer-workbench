import type { FindingDetailPublic, FindingExplanationPublic } from "@/api-client"
import {
  arrayRecords,
  joinedValues,
  objectRecord,
  stringValue,
} from "@/lib/app-errors"
import { formatEpss, formatNullableNumber } from "@/lib/risk-format"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"
import type { FindingWaiverEvidence } from "@/lib/waiver-view"

import {
  attackContextEmptyState,
  attackTechniqueRows,
} from "./finding-detail-attack-model"
import {
  decisionReasonDetail,
  decisionReasonLabel,
  findingAssetLabel,
  findingRecommendedAction,
  findingWhyText,
  isInternetFacingExposure,
  isProductionEnvironment,
  type FindingAttackContext,
  type FindingDecisionReason,
  type FindingDetailRow,
  type FindingOccurrenceRow,
} from "./finding-detail-shared"

export function findingOccurrenceRows(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
): FindingOccurrenceRow[] {
  if (finding?.occurrences?.length) {
    return finding.occurrences
  }
  const explanationPayload = objectRecord(explanation?.explanation)
  const explanationProvenance = objectRecord(explanationPayload.provenance)
  const findingProvenance = objectRecord(
    objectRecord(finding?.explanation_json).provenance,
  )
  return arrayRecords(
    explanationProvenance.occurrences ?? findingProvenance.occurrences,
  ).map((occurrence, index) => ({
    ...occurrence,
    id: stringValue(occurrence.id) ?? `occurrence-${index + 1}`,
  }))
}

export function findingDecisionReasonRows(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
  attackContext: FindingAttackContext | null,
) {
  const rows: FindingDecisionReason[] = []

  if (finding?.in_kev) {
    rows.push({
      detail:
        "CISA KEV is recorded for this CVE, so exploitation is a confirmed prioritization signal.",
      label: "CISA KEV listed",
      tone: "critical",
    })
  }

  if (finding?.epss !== null && finding?.epss !== undefined) {
    rows.push({
      detail:
        finding.epss >= 0.7
          ? `${formatEpss(finding.epss)} EPSS indicates elevated exploitation probability.`
          : `${formatEpss(finding.epss)} EPSS is recorded for the decision model.`,
      label: finding.epss >= 0.7 ? "High EPSS" : "EPSS recorded",
      tone: finding.epss >= 0.7 ? "warning" : "info",
    })
  }

  if (
    finding?.cvss_base_score !== null &&
    finding?.cvss_base_score !== undefined
  ) {
    rows.push({
      detail:
        finding.cvss_base_score >= 9
          ? `CVSS ${formatNullableNumber(finding.cvss_base_score)} is critical impact severity.`
          : `CVSS ${formatNullableNumber(finding.cvss_base_score)} contributes to the risk score.`,
      label: finding.cvss_base_score >= 9 ? "Critical CVSS" : "CVSS recorded",
      tone: finding.cvss_base_score >= 9 ? "critical" : "info",
    })
  }

  if (finding && isInternetFacingExposure(finding.exposure)) {
    rows.push({
      detail: `${findingAssetLabel(finding)} is marked ${labelize(finding.exposure)}, increasing remediation urgency.`,
      label: "Internet-facing asset",
      tone: "critical",
    })
  }

  if (isProductionEnvironment(finding?.asset_environment)) {
    rows.push({
      detail: `Environment is marked ${labelize(finding?.asset_environment)}, so operational exposure is higher.`,
      label: "Production service",
      tone: "warning",
    })
  }

  if (!attackContextEmptyState(attackContext)) {
    rows.push({
      detail: `${attackTechniqueRows(attackContext).length} reviewed ATT&CK technique mapping(s) are available for defensive context.`,
      label: "ATT&CK / TTP context",
      tone: "warning",
    })
  }

  const defensiveNote = stringValue(attackContext?.defensive_note)
  if (defensiveNote && /gap|missing|coverage|detect/i.test(defensiveNote)) {
    rows.push({
      detail: defensiveNote,
      label: "Detection coverage gap",
      tone: "warning",
    })
  }

  const recommendedAction = findingRecommendedAction(finding, explanation)
  if (recommendedAction !== "No recommended action has been recorded.") {
    rows.push({
      detail: recommendedAction,
      label: "Fix or mitigation",
      tone: "positive",
    })
  }

  if (rows.length === 0) {
    rows.push({
      detail: findingWhyText(finding, explanation),
      label: "Decision rationale",
      tone: "info",
    })
  }

  return rows
}

export function findingReasonRows(
  explanation: FindingExplanationPublic | null,
) {
  const decisionExplanation = objectRecord(explanation?.decision_explanation)
  const reasons = arrayRecords(decisionExplanation.reasons)
  return reasons.map((reason, index) => {
    const code =
      stringValue(reason.code) ??
      stringValue(reason.signal) ??
      stringValue(reason.source)
    const detail =
      decisionReasonDetail(
        code,
        stringValue(reason.message) ??
          stringValue(reason.description) ??
          stringValue(reason.detail) ??
          stringValue(reason.value) ??
          null,
      ) ?? "Matched decision signal"
    return {
      detail,
      label: code ? decisionReasonLabel(code) : `Reason ${index + 1}`,
    }
  })
}

export function findingDataQualityRows(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
) {
  const flags =
    explanation?.data_quality_flags ??
    arrayRecords(objectRecord(finding?.data_quality_json).flags)
  return flags.map((flag, index) => ({
    code: stringValue(flag.code) ?? "data_quality_flag",
    key: [flag.source, flag.code, flag.message, index].join(":"),
    message: stringValue(flag.message) ?? "Data quality flag recorded.",
    severity: stringValue(flag.severity) ?? "info",
    source: stringValue(flag.source) ?? "provider",
  }))
}

export function findingProviderGaps(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
) {
  if (!finding) {
    return []
  }
  const providerEvidence = objectRecord(
    explanation?.provider_evidence ??
      objectRecord(finding.explanation_json).provider_evidence,
  )
  const gaps: string[] = []
  if (finding.epss === null || finding.epss === undefined) {
    gaps.push("EPSS missing")
  }
  if (
    finding.cvss_base_score === null ||
    finding.cvss_base_score === undefined
  ) {
    gaps.push("CVSS missing")
  }
  if (Object.keys(providerEvidence).length === 0) {
    gaps.push("Provider evidence missing")
  }
  return gaps
}

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
          ? dataQualityRows.map((row) => labelize(row.code)).join(", ")
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
      .find((value) => value !== "N.A.") ?? null

  return [
    {
      detail: "Initial source occurrence recorded by Workbench.",
      label: "First seen",
      value: finding?.first_seen_at
        ? formatFindingDateTime(finding.first_seen_at)
        : "N.A.",
    },
    {
      detail: "Most recent source occurrence recorded by Workbench.",
      label: "Last seen",
      value: finding?.last_seen_at
        ? formatFindingDateTime(finding.last_seen_at)
        : "N.A.",
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
