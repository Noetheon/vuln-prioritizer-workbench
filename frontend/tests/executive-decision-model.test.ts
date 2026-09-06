import assert from "node:assert/strict"
import test from "node:test"
import type { AnalysisRunSummaryPublic } from "../src/api-client"
import { executiveDecisionFacts } from "../src/components/reports/executive-decision-model.ts"

const runFixture: AnalysisRunSummaryPublic = {
  id: "run-1",
  project_id: "project-1",
  input_type: "cve-list",
  filename: null,
  started_at: "2026-01-01T00:00:00Z",
  finished_at: null,
  status: "succeeded",
}

test("legacy critical counts never fabricate business context or a remediation SLA", () => {
  const facts = executiveDecisionFacts({
    ...runFixture,
    finding_count: 2,
    kev_hits: 1,
    counts_by_priority: { Critical: 2 },
  } as AnalysisRunSummaryPublic)
  assert.equal(
    facts.problem,
    "2 findings recorded in this run; 1 appear in the KEV catalog.",
  )
  assert.equal(facts.sla, "No actionable SLA was recorded for this run.")
  assert.equal(
    facts.recommendations,
    "No structured decision guidance was recorded for this run.",
  )
  assert.deepEqual(facts.decisions, [])
  assert.doesNotMatch(JSON.stringify(facts), /production|exploitation|48 hours/)
})

test("the executive model renders the recorded policy and guidance coverage", () => {
  const facts = executiveDecisionFacts({
    ...runFixture,
    finding_count: 3,
    kev_hits: 0,
    decision_summary: {
      finding_count: 3,
      actionable_finding_count: 2,
      findings_with_guidance: 2,
      missing_guidance_count: 1,
      recommendation_counts: { Patch: 1, Review: 1 },
      shortest_actionable_sla: {
        priority: "Critical",
        label: "Within 6 hours",
        target_hours: 6,
        guidance: "Confirm the supplied scope.",
        source: "custom",
      },
      top_decisions: [],
    },
  } as AnalysisRunSummaryPublic)
  assert.equal(facts.sla, "Within 6 hours. Confirm the supplied scope.")
  assert.equal(facts.recommendations, "Patch: 1 · Review: 1")
  assert.match(facts.coverage, /2 of 3 findings; 1 have no recorded guidance/)
})

test("missing run data remains explicit", () => {
  const facts = executiveDecisionFacts(null)
  assert.equal(
    facts.problem,
    "No finding summary is available for the selected run.",
  )
  assert.equal(
    facts.coverage,
    "Decision guidance coverage is unavailable for this run.",
  )
})
