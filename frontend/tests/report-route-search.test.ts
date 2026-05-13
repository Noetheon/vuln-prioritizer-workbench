import assert from "node:assert/strict"
import test from "node:test"

import {
  normalizeSelectedRunId,
  reportRunUrlSearch,
  selectedReportRunIdFromSearch,
} from "../src/workbench/report-route-search.ts"

test("reads selected report run id from route search", () => {
  assert.equal(selectedReportRunIdFromSearch("?runId=run-1"), "run-1")
  assert.equal(selectedReportRunIdFromSearch("projectId=project-1"), "")
})

test("updates report run id while preserving project search", () => {
  assert.deepEqual(
    reportRunUrlSearch("?projectId=project-1&runId=old&tab=reports", "run-2"),
    {
      projectId: "project-1",
      runId: "run-2",
      tab: "reports",
    },
  )
  assert.deepEqual(
    reportRunUrlSearch("?projectId=project-1&runId=old", ""),
    {
      projectId: "project-1",
    },
  )
})

test("normalizes stale report run ids to an available run", () => {
  assert.equal(
    normalizeSelectedRunId(["missing", "run-2"], ["run-1", "run-2"]),
    "run-2",
  )
  assert.equal(normalizeSelectedRunId(["missing"], ["run-1"]), "run-1")
  assert.equal(normalizeSelectedRunId(["missing"], []), "")
})
