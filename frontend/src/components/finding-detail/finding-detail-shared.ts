import type {
  FindingDetailPublic,
  FindingExplanationPublic,
  FindingOccurrencePublic,
  FindingPriority,
} from "@/api-client"
import { joinedValues, objectRecord, stringValue } from "@/lib/app-errors"
import { formatEpss, formatNullableNumber } from "@/lib/risk-format"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"

export type FindingAttackContext = NonNullable<
  FindingDetailPublic["attack_context"]
>

export type FindingDecisionReason = {
  detail: string
  label: string
  tone: "critical" | "warning" | "info" | "positive"
}

export type FindingDetailRow = {
  detail?: string
  label: string
  value: string
}

export type FindingOccurrenceRow = Partial<FindingOccurrencePublic> &
  Record<string, unknown>

const decisionReasonCopy: Record<string, { label: string; detail: string }> = {
  "asset.context": {
    detail: "Asset context influences operational priority.",
    label: "Asset context",
  },
  "asset.context_unknown": {
    detail:
      "Asset context is missing and must be validated before final scheduling.",
    label: "Asset context unknown",
  },
  "operational.score": {
    detail: "Combined signals determine the operational remediation score.",
    label: "Operational score",
  },
  "priority.critical.epss_cvss": {
    detail: "EPSS and CVSS together indicate critical remediation urgency.",
    label: "Critical EPSS and CVSS",
  },
  "priority.high.cvss": {
    detail: "CVSS indicates high impact severity.",
    label: "High CVSS",
  },
  "priority.high.epss": {
    detail: "EPSS indicates elevated exploitation probability.",
    label: "High EPSS",
  },
  "priority.kev.known_exploited": {
    detail: "Known exploited vulnerability signal is present.",
    label: "Known exploited vulnerability",
  },
  "priority.medium.cvss": {
    detail: "CVSS contributes meaningful impact severity.",
    label: "Medium CVSS signal",
  },
  "priority.medium.epss": {
    detail: "EPSS contributes exploitation probability context.",
    label: "Medium EPSS signal",
  },
}

export function humanizeDecisionReasonText(value: string | null | undefined) {
  if (!value) {
    return value
  }
  return Object.entries(decisionReasonCopy).reduce(
    (text, [code, copy]) =>
      text.replaceAll(code, copy.detail.replace(/\.$/, "")),
    value,
  )
}

export function decisionReasonLabel(value: string | null | undefined) {
  if (!value) {
    return "Reason"
  }
  return decisionReasonCopy[value]?.label ?? labelize(value)
}

export function decisionReasonDetail(
  code: string | null | undefined,
  detail: string | null | undefined,
) {
  return (
    humanizeDecisionReasonText(detail) ?? decisionReasonCopy[code ?? ""]?.detail
  )
}

export function findingWhyText(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
) {
  const decisionExplanation = objectRecord(explanation?.decision_explanation)
  const fallback = "No priority explanation has been recorded for this finding."
  return (
    humanizeDecisionReasonText(
      stringValue(decisionExplanation.human_readable) ??
        stringValue(decisionExplanation.summary) ??
        explanation?.rationale ??
        finding?.rationale ??
        fallback,
    ) ?? fallback
  )
}

function summaryList(values: readonly string[]) {
  if (values.length <= 1) {
    return values[0] ?? ""
  }
  if (values.length === 2) {
    return `${values[0]} and ${values[1]}`
  }
  return `${values.slice(0, -1).join(", ")}, and ${values.at(-1)}`
}

function firstCompactSentence(value: string, maxLength = 190) {
  const trimmed = value.trim()
  const firstSentence = trimmed.match(/^(.+?[.!?])(?:\s|$)/)?.[1] ?? trimmed
  if (firstSentence.length <= maxLength) {
    return firstSentence
  }
  const words = firstSentence.split(/\s+/)
  let compact = ""
  for (const word of words) {
    const candidate = compact ? `${compact} ${word}` : word
    if (candidate.length > maxLength - 3) {
      break
    }
    compact = candidate
  }
  return `${compact || firstSentence.slice(0, maxLength - 3).trimEnd()}...`
}

export function findingHeroSummary(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
) {
  if (!finding) {
    return findingWhyText(finding, explanation)
  }

  const signals: string[] = []
  if (finding.in_kev) {
    signals.push("CISA KEV")
  }
  if (finding.epss !== null && finding.epss !== undefined) {
    signals.push(`${formatEpss(finding.epss)} EPSS`)
  }
  if (
    finding.cvss_base_score !== null &&
    finding.cvss_base_score !== undefined
  ) {
    signals.push(`CVSS ${formatNullableNumber(finding.cvss_base_score)}`)
  }
  if (isInternetFacingExposure(finding.exposure)) {
    signals.push(`${labelize(finding.exposure)} exposure`)
  }
  if (isProductionEnvironment(finding.asset_environment)) {
    signals.push(`${labelize(finding.asset_environment)} environment`)
  }

  if (signals.length > 0) {
    const priority =
      finding.priority && labelize(finding.priority) !== "N.A."
        ? `${labelize(finding.priority)} priority`
        : "Priority"
    return `${priority} combines ${summaryList(signals)}.`
  }

  return firstCompactSentence(findingWhyText(finding, explanation))
}

export function findingRecommendedAction(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
) {
  const decisionGuidance = objectRecord(explanation?.decision_guidance)
  return (
    stringValue(decisionGuidance.recommended_action) ??
    explanation?.recommended_action ??
    finding?.recommended_action ??
    "No recommended action has been recorded."
  )
}

export function findingComponentDetailLabel(
  finding: FindingDetailPublic | null,
) {
  if (!finding) {
    return "N.A."
  }
  const name = optionalText(finding.component_name)
  return finding.component_version
    ? `${name} ${finding.component_version}`
    : name
}

export function findingAssetServiceDetailLabel(
  finding: FindingDetailPublic | null,
) {
  if (!finding) {
    return "N.A."
  }
  return joinedValues([
    finding.business_service,
    finding.asset_name,
    finding.asset_key,
    finding.asset_target_ref,
  ])
}

export function findingOwnerDetailLabel(
  finding: FindingDetailPublic | null,
  occurrences: readonly FindingOccurrenceRow[],
) {
  return (
    finding?.owner ?? stringValue(occurrences[0]?.asset_owner) ?? "Unassigned"
  )
}

export function findingSlaLabel(priority: FindingPriority | undefined) {
  switch (priority) {
    case "critical":
      return "24 hours"
    case "high":
      return "7 days"
    case "medium":
      return "30 days"
    case "low":
      return "90 days"
    default:
      return "Define during triage"
  }
}

export function findingNextStepLabel(finding: FindingDetailPublic | null) {
  switch (finding?.status) {
    case "open":
      return "Assign remediation work and start fix validation."
    case "in_review":
      return "Complete technical review and confirm the remediation path."
    case "remediating":
      return "Verify the fix, then update evidence and status."
    case "fixed":
      return "Confirm scanner closure and keep evidence for reporting."
    case "accepted":
      return "Track accepted risk until the next review date."
    case "suppressed":
      return "Verify the VEX or suppression scope still applies."
    default:
      return "Confirm ownership and record the next remediation step."
  }
}

export function findingAssetLabel(finding: FindingDetailPublic) {
  return (
    finding.asset_name ??
    finding.asset_key ??
    finding.business_service ??
    "N.A."
  )
}

export function isInternetFacingExposure(value: string | null | undefined) {
  return value ? value.toLowerCase().includes("internet") : false
}

export function isProductionEnvironment(value: string | null | undefined) {
  return value ? /\bprod(uction)?\b/i.test(value.replaceAll("_", " ")) : false
}
