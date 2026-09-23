import type { FindingPublic } from "../api-client"

export function findingSlaLabel(finding: Pick<FindingPublic, "evidence" | "sla">) {
  const sla = finding.sla ?? finding.evidence?.remediation?.sla
  const label = sla?.label
  if (typeof label !== "string" || !label.trim()) return "No SLA recorded"
  if (
    typeof sla?.target_hours === "number" &&
    Number.isFinite(sla.target_hours)
  ) {
    return `${label.trim()} · ${sla.target_hours}h`
  }
  if (
    typeof sla?.target_days === "number" &&
    Number.isFinite(sla.target_days)
  ) {
    return `${label.trim()} · ${sla.target_days}d`
  }
  return label.trim()
}
