import type { FindingPublic, FindingStatus } from "@/api-client"

// Queue-safe urgency copy built from list-row finding signals.
const HIGH_EPSS_THRESHOLD = 0.7
const CRITICAL_CVSS_THRESHOLD = 9

export function findingWhyNow(finding: FindingPublic) {
  const governance = governanceWhyNow(finding)
  if (governance) return governance

  const signals = signalDrivers(finding)
  const context = contextDrivers(finding)
  const status = statusDriver(finding.status)

  if (signals.length > 0 || context.length > 0) {
    const lead =
      signals.length > 0
        ? `${summaryList(signals)} ${signals.length === 1 ? "is" : "are"} active`
        : "Asset context raises operational urgency"
    const contextText =
      context.length > 0 ? ` on ${summaryList(context)}` : ""
    const statusText = status ? `; ${status}` : ""
    return `${lead}${contextText}${statusText}.`
  }

  return textOr(finding.rationale, "No priority rationale has been recorded yet.")
}

export function findingWhyNowCompact(finding: FindingPublic) {
  const why = findingWhyNow(finding)
  const firstSentence = why.match(/^(.+?[.!?])(?:\s|$)/)?.[1] ?? why
  if (firstSentence.length <= 118) return firstSentence
  return `${firstSentence.slice(0, 115).trimEnd()}...`
}

function governanceWhyNow(finding: FindingPublic) {
  const context = contextDrivers(finding)
  const contextText = context.length > 0 ? ` for ${summaryList(context)}` : ""
  const signals = signalDrivers(finding)
  const signalText =
    signals.length > 0
      ? `${summaryList(signals)} ${signals.length === 1 ? "remains" : "remain"} visible; `
      : ""

  if (finding.suppressed_by_vex || finding.status === "suppressed") {
    return `Evidence review: ${signalText}VEX suppression keeps the finding out of active remediation${contextText}.`
  }

  if (finding.status === "fixed") {
    return `Verification: fixed evidence remains visible${contextText} until follow-up evidence confirms closure.`
  }

  if (finding.waived || finding.status === "accepted") {
    return `Governance review: ${signalText}accepted risk stays on owner review cadence${contextText}.`
  }

  if (finding.under_investigation || finding.status === "in_review") {
    return `Owner review: ${signalText || "evidence is incomplete; "}the finding remains visible while scope is confirmed${contextText}.`
  }

  return null
}

function signalDrivers(finding: FindingPublic) {
  const signals: string[] = []
  if (finding.in_kev) {
    signals.push("CISA KEV")
  }
  if (finding.epss !== null && finding.epss !== undefined) {
    if (finding.epss >= HIGH_EPSS_THRESHOLD) {
      signals.push(`EPSS ${formatPercent(finding.epss)}`)
    }
  }
  if (
    finding.cvss_base_score !== null &&
    finding.cvss_base_score !== undefined &&
    finding.cvss_base_score >= CRITICAL_CVSS_THRESHOLD
  ) {
    signals.push(`CVSS ${formatScore(finding.cvss_base_score)}`)
  }
  return signals
}

function contextDrivers(finding: FindingPublic) {
  const context: string[] = []
  if (isInternetFacing(finding.exposure)) {
    context.push("internet-facing exposure")
  } else if (isDmz(finding.exposure)) {
    context.push("DMZ exposure")
  }
  if (isProduction(finding.asset_environment)) {
    context.push("production")
  }
  const criticality = criticalityDriver(finding.asset_criticality)
  if (criticality) {
    context.push(criticality)
  }
  if (context.length === 0 && finding.business_service) {
    context.push(`${finding.business_service} service`)
  }
  return context
}

function statusDriver(status: FindingStatus | undefined) {
  switch (status) {
    case "open":
      return "remediation work is open"
    case "remediating":
      return "remediation is already in progress"
    default:
      return null
  }
}

function textOr(value: string | null | undefined, fallback: string) {
  return value?.trim() ? value : fallback
}

function isInternetFacing(value: string | null | undefined) {
  return normalize(value) === "internet-facing"
}

function isDmz(value: string | null | undefined) {
  return normalize(value) === "dmz"
}

function isProduction(value: string | null | undefined) {
  return ["prod", "production"].includes(normalize(value))
}

function criticalityDriver(value: string | null | undefined) {
  const normalized = normalize(value)
  if (normalized === "critical") return "critical asset"
  if (normalized === "high") return "high-criticality asset"
  return null
}

function normalize(value: string | null | undefined) {
  return value?.trim().toLowerCase() ?? ""
}

function formatPercent(value: number) {
  return `${Math.round(value * 100)}%`
}

function formatScore(value: number) {
  return value.toFixed(1)
}

function summaryList(values: readonly string[]) {
  if (values.length <= 1) return values[0] ?? ""
  if (values.length === 2) return `${values[0]} and ${values[1]}`
  return `${values.slice(0, -1).join(", ")}, and ${values.at(-1)}`
}
