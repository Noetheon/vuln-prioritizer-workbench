import assert from "node:assert/strict"
import test from "node:test"

import {
  importRunUrlSearch,
  normalizeSelectedRunId,
  selectedImportRunIdFromSearch,
} from "../src/workbench/import-route-search.ts"

test("reads selected import run id from route search", () => {
  assert.equal(selectedImportRunIdFromSearch("?runId=run-1"), "run-1")
  assert.equal(selectedImportRunIdFromSearch("projectId=project-1"), "")
})

test("updates import run id while preserving project search", () => {
  assert.deepEqual(
    importRunUrlSearch("?projectId=project-1&runId=old&tab=imports", "run-2"),
    {
      projectId: "project-1",
      runId: "run-2",
      tab: "imports",
    },
  )
  assert.deepEqual(
    importRunUrlSearch("?projectId=project-1&runId=old", ""),
    {
      projectId: "project-1",
    },
  )
})

test("normalizes stale import run ids to an available run", () => {
  assert.equal(
    normalizeSelectedRunId(["missing", "run-2"], ["run-1", "run-2"]),
    "run-2",
  )
  assert.equal(normalizeSelectedRunId(["missing"], ["run-1"]), "run-1")
  assert.equal(normalizeSelectedRunId(["missing"], []), "")
})
