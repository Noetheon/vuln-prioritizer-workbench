import type { DecisionRevisionPublic } from "../../api-client"

const comparedFields = [
  ["priority", "Priority"],
  ["status", "Status"],
  ["risk_score", "Risk score"],
  ["operational_rank", "Operational rank"],
  ["rationale", "Rationale"],
  ["recommended_action", "Recommended action"],
  ["provider_snapshot_id", "Provider snapshot"],
  ["engine_version", "Engine version"],
] as const

export function revisionDifferenceRows(
  current: DecisionRevisionPublic,
  previous?: DecisionRevisionPublic,
) {
  if (!previous) return []
  return comparedFields.flatMap(([field, label]) => {
    const before = previous[field]
    const after = current[field]
    return before === after
      ? []
      : [
          {
            field,
            label,
            before: String(before ?? "Not recorded"),
            after: String(after ?? "Not recorded"),
          },
        ]
  })
}
