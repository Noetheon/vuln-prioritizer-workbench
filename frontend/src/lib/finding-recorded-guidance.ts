import type { FindingPublic } from "../api-client"

export function findingSlaLabel(finding: Pick<FindingPublic, "evidence" | "sla">) {
  const sla = finding.sla ?? finding.evidence?.remediation?.sla
  const label = sla?.label
  if (typeof label !== "string" || !label.trim()) return "No SLA recorded"
  const target = slaTargetText(sla?.target_hours, sla?.target_days)
  return target ? `${label.trim()} · ${target}` : label.trim()
}

// Whole days read better than hours: a 720-hour target is "30 days".
function slaTargetText(hours: unknown, days: unknown) {
  if (typeof hours === "number" && Number.isFinite(hours)) {
    return hours > 0 && hours % 24 === 0
      ? countText(hours / 24, "day")
      : countText(hours, "hour")
  }
  if (typeof days === "number" && Number.isFinite(days)) {
    return countText(days, "day")
  }
  return ""
}

function countText(count: number, unit: string) {
  return `${count} ${unit}${count === 1 ? "" : "s"}`
}
