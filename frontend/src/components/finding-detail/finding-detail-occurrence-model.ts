import type { FindingDetailPublic, FindingExplanationPublic } from "@/api-client"
import {
  arrayRecords,
  objectRecord,
  stringValue,
} from "@/lib/app-errors"
import type { FindingOccurrenceRow } from "./finding-detail-shared"

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
