import assert from "node:assert/strict"
import test from "node:test"

import {
  invalidateProjectScopedWorkbenchQueries,
  invalidateWorkbenchProjectQueries,
  workbenchQueryKeys,
} from "../src/workbench/workbench-query-keys.ts"

function invalidator() {
  const calls: unknown[][] = []
  return {
    calls,
    queryClient: {
      async invalidateQueries({ queryKey }: { queryKey: unknown[] }) {
        calls.push(queryKey)
      },
    },
  }
}

test("workbench query keys expose project-scoped invalidation roots", () => {
  assert.deepEqual(workbenchQueryKeys.findingsRoot(), ["workbench", "findings"])
  assert.deepEqual(workbenchQueryKeys.assetsRoot("project-1"), [
    "workbench",
    "assets",
    "project-1",
  ])
  assert.deepEqual(workbenchQueryKeys.assetFindingsRoot("project-1"), [
    "workbench",
    "asset-findings",
    "project-1",
  ])
  assert.deepEqual(workbenchQueryKeys.reportsRoot(), ["workbench", "reports"])
  assert.deepEqual(workbenchQueryKeys.projectSummariesRoot(), [
    "workbench",
    "project-summaries",
  ])
  assert.deepEqual(workbenchQueryKeys.projectSummaryRoot(), [
    "workbench",
    "project-summary",
  ])
  assert.deepEqual(workbenchQueryKeys.projectDashboard("project-1"), [
    "workbench",
    "project-dashboard",
    "project-1",
  ])
})

test("project list invalidation uses the shared project roots", async () => {
  const { calls, queryClient } = invalidator()

  await invalidateWorkbenchProjectQueries(queryClient)

  assert.deepEqual(calls, [
    workbenchQueryKeys.projects(),
    workbenchQueryKeys.projectSummariesRoot(),
    workbenchQueryKeys.projectSummaryRoot(),
  ])
})

test("project-scoped invalidation covers route data that can change by project", async () => {
  const { calls, queryClient } = invalidator()

  await invalidateProjectScopedWorkbenchQueries(queryClient, "project-1")

  assert.deepEqual(calls, [
    workbenchQueryKeys.projectSummary("project-1"),
    workbenchQueryKeys.projectDashboard("project-1"),
    workbenchQueryKeys.projectSummariesRoot(),
    workbenchQueryKeys.projectRuns("project-1"),
    workbenchQueryKeys.findingsRoot(),
    workbenchQueryKeys.projectGovernanceRollups("project-1"),
    workbenchQueryKeys.waivers("project-1"),
    workbenchQueryKeys.assetsRoot("project-1"),
    workbenchQueryKeys.assetFindingsRoot("project-1"),
    workbenchQueryKeys.reportsRoot(),
  ])
})
