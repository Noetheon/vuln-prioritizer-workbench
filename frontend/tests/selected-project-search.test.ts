import assert from "node:assert/strict"
import test from "node:test"

import {
  searchStringFromUrlSearch,
  selectedProjectIdFromSearch,
  selectedProjectUrlSearch,
} from "../src/workbench/selected-project-search.ts"

test("reads selected project id from route search", () => {
  assert.equal(selectedProjectIdFromSearch("?projectId=project-1"), "project-1")
  assert.equal(selectedProjectIdFromSearch("status=open"), "")
})

test("updates project id in route search while preserving other keys", () => {
  assert.deepEqual(
    selectedProjectUrlSearch("?status=open&projectId=old&sort=score", "next"),
    {
      projectId: "next",
      sort: "score",
      status: "open",
    },
  )
  assert.equal(
    searchStringFromUrlSearch(
      selectedProjectUrlSearch("?status=open&projectId=old", ""),
    ),
    "status=open",
  )
})
