import assert from "node:assert/strict"
import test from "node:test"

import type { MitigationLeverPublic } from "../src/api-client"
import {
  buildRiskScenario,
  groupMitigationLeversByLane,
  riskLeverSearchWithSelection,
  selectedRiskLeverIdsFromSearch,
} from "../src/components/dashboard/dashboard-risk-scenario-model.ts"

function lever(
  value: Partial<MitigationLeverPublic> & {
    action_label: string
    lever_id: string
  },
): MitigationLeverPublic {
  return {
    action_label: value.action_label,
    kind: value.kind ?? "recommended_action",
    lever_id: value.lever_id,
    resolved_finding_count: value.resolved_finding_count ?? 1,
    resolved_kev_count: value.resolved_kev_count ?? 0,
    risk_score_sum: value.risk_score_sum ?? 0,
    roadmap_lane: value.roadmap_lane ?? "later",
    ...value,
  } as MitigationLeverPublic
}

test("defaults URL selection to the recommended lever", () => {
  const levers = [
    lever({ action_label: "Patch edge", lever_id: "a" }),
    lever({ action_label: "Rotate keys", lever_id: "b" }),
  ]

  assert.deepEqual(selectedRiskLeverIdsFromSearch("?projectId=p1", levers, "b"), [
    "b",
  ])
  assert.deepEqual(
    selectedRiskLeverIdsFromSearch(
      "?projectId=p1&riskLevers=missing,a",
      levers,
      "b",
    ),
    ["a"],
  )
})

test("keeps explicit empty URL selection shareable", () => {
  const levers = [lever({ action_label: "Patch edge", lever_id: "a" })]

  assert.deepEqual(
    selectedRiskLeverIdsFromSearch("?riskLevers=none", levers, "a"),
    [],
  )
  assert.equal(
    riskLeverSearchWithSelection("?projectId=p1&tab=dashboard", []).toString(),
    "projectId=p1&tab=dashboard&riskLevers=none",
  )
})

test("serializes selected levers while preserving other query params", () => {
  const search = riskLeverSearchWithSelection(
    "?projectId=p1&riskLevers=old&tab=dashboard",
    ["a", "b", "a"],
  )

  assert.equal(search.get("projectId"), "p1")
  assert.equal(search.get("tab"), "dashboard")
  assert.equal(search.get("riskLevers"), "a,b")
})

test("calculates projected average from disjoint selected levers", () => {
  const levers = [
    lever({
      action_label: "Patch edge",
      lever_id: "a",
      resolved_finding_count: 2,
      resolved_kev_count: 1,
      risk_score_sum: 80,
    }),
    lever({
      action_label: "Rotate keys",
      lever_id: "b",
      resolved_finding_count: 1,
      risk_score_sum: 20,
    }),
  ]

  const scenario = buildRiskScenario({
    baselineAverageRiskScore: 33.3,
    baselineOpenFindingCount: 3,
    baselineTotalRiskScore: 100,
    levers,
    riskTargetScore: 30,
    selectedLeverIds: ["a"],
  })

  assert.equal(scenario.riskRemovedScore, 80)
  assert.equal(scenario.riskRemovedPercent, 80)
  assert.equal(scenario.totalFindingsResolved, 2)
  assert.equal(scenario.kevResolved, 1)
  assert.equal(scenario.remainingOpenFindingCount, 1)
  assert.equal(scenario.projectedAverageRiskScore, 20)
  assert.equal(scenario.averageDelta, 13.3)
  assert.equal(scenario.targetGap, -10)
})

test("groups mitigation levers into roadmap lanes with safe fallback", () => {
  const grouped = groupMitigationLeversByLane([
    lever({ action_label: "Patch edge", lever_id: "a", roadmap_lane: "now" }),
    lever({ action_label: "Rotate keys", lever_id: "b", roadmap_lane: "next" }),
    lever({ action_label: "Inventory", lever_id: "c", roadmap_lane: "unknown" }),
  ])

  assert.deepEqual(
    Object.fromEntries(
      Object.entries(grouped).map(([lane, laneLevers]) => [
        lane,
        laneLevers.map((item) => item.lever_id),
      ]),
    ),
    {
      later: ["c"],
      next: ["b"],
      now: ["a"],
    },
  )
})
