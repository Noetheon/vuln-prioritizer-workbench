import type { AnalysisRunSummaryPublic } from "../../api-client"

export function executiveDecisionFacts(
  summary: AnalysisRunSummaryPublic | null,
) {
  const decision = summary?.decision_summary
  const total = summary?.finding_count ?? 0
  const guidance = decision?.findings_with_guidance ?? 0
  const sla = decision?.shortest_actionable_sla
  return {
    problem: summary
      ? `${total} findings recorded in this run; ${summary.kev_hits} appear in the KEV catalog.`
      : "No finding summary is available for the selected run.",
    recommendations:
      decision && guidance > 0
        ? Object.entries(decision.recommendation_counts ?? {})
            .map(([label, count]) => `${label}: ${count}`)
            .join(" · ")
        : "No structured decision guidance was recorded for this run.",
    sla: sla
      ? `${sla.label}. ${sla.guidance}`
      : "No actionable SLA was recorded for this run.",
    coverage: decision
      ? `${decision.actionable_finding_count ?? 0} actionable findings at evaluation time. Structured guidance is recorded for ${guidance} of ${decision.finding_count ?? total} findings${(decision.missing_guidance_count ?? 0) > 0 ? `; ${decision.missing_guidance_count} have no recorded guidance` : ""}.`
      : "Decision guidance coverage is unavailable for this run.",
    decisions: decision?.top_decisions ?? [],
  }
}
