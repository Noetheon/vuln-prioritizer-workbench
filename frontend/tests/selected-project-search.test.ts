import assert from "node:assert/strict"
import test from "node:test"

import {
  assetFindingsUrlSearch,
  normalizeSelectedProjectId,
  projectSwitchLocation,
  searchStringFromUrlSearch,
  selectedProjectIdFromSearch,
  selectedProjectRouteSearch,
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

test("builds route search for project-aware navigation", () => {
  assert.deepEqual(selectedProjectRouteSearch("project-1"), {
    projectId: "project-1",
  })
  assert.deepEqual(selectedProjectRouteSearch(""), {})
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

test("switching project keeps filters but drops the old project's page, run, and asset", () => {
  assert.deepEqual(
    projectSwitchLocation(
      "/triage",
      "?projectId=old&priority=critical&offset=50&assetId=a-1&assetKey=web",
      "next",
    ),
    { search: "projectId=next&priority=critical", to: "/triage" },
  )
  assert.deepEqual(
    projectSwitchLocation("/evidence", "runId=run-1&projectId=old", "next"),
    { search: "projectId=next", to: "/evidence" },
  )
  assert.deepEqual(projectSwitchLocation("/", "", "next"), {
    search: "projectId=next",
    to: "/",
  })
})

test("switching project from a finding or import run returns to its list", () => {
  assert.deepEqual(
    projectSwitchLocation("/findings/finding-1", "?projectId=old&status=open", "next"),
    { search: "projectId=next&status=open", to: "/triage" },
  )
  assert.deepEqual(
    projectSwitchLocation("/imports/runs/run-1/", "?projectId=old", "next"),
    { search: "projectId=next", to: "/imports" },
  )
  assert.deepEqual(
    projectSwitchLocation("/imports/new", "?projectId=old", "next"),
    { search: "projectId=next", to: "/imports/new" },
  )
})
