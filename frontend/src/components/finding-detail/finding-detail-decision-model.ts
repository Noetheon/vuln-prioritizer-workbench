import type { FindingDetailPublic, FindingExplanationPublic } from "@/api-client"
import {
  arrayRecords,
  objectRecord,
  stringValue,
} from "@/lib/app-errors"
import { formatEpss, formatNullableNumber } from "@/lib/risk-format"
import { formatLabel as labelize } from "@/lib/ui-copy"
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
} from "./finding-detail-shared"

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
