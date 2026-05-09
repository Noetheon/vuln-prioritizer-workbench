import assert from "node:assert/strict"
import test from "node:test"

import {
  assetFindingsUrlSearch,
  normalizeSelectedProjectId,
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

test("normalizes stale selected project ids to an available project", () => {
  assert.equal(
    normalizeSelectedProjectId(
      ["deleted-project", "project-2"],
      ["project-1", "project-2"],
    ),
    "project-2",
  )
  assert.equal(
    normalizeSelectedProjectId(
      ["deleted-project", "also-deleted"],
      ["project-1", "project-2"],
    ),
    "project-1",
  )
  assert.equal(normalizeSelectedProjectId(["deleted-project"], []), "")
})

test("serializes asset findings links with project and asset identity", () => {
  assert.equal(
    searchStringFromUrlSearch(
      assetFindingsUrlSearch({
        assetId: "asset-1",
        assetKey: "build-host-1",
        projectId: "project-1",
      }),
    ),
    "projectId=project-1&assetId=asset-1&assetKey=build-host-1",
  )
})
