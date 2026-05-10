import assert from "node:assert/strict"
import test from "node:test"

import {
  clearFindingsFilters,
  cleanFindingsSearchQueryString,
  defaultFindingsSearchState,
  findingsSearchQueryString,
  findingsSearchToApiParams,
  findingsSearchToFilters,
  findingsSearchToUrlSearch,
  parseFindingsSearch,
  updateFindingsSearch,
} from "../src/components/findings/findings-search-state.ts"

function definedSearch(search: Record<string, unknown>) {
  return Object.fromEntries(
    Object.entries(search).filter((entry) => entry[1] !== undefined),
  )
}

test("findings search parser validates invalid URL params back to defaults", () => {
  const state = parseFindingsSearch({
    assetKey: "ignored-without-asset",
    cvssMax: "42",
    direction: "sideways",
    epssMin: "not-a-number",
    kev: "maybe",
    limit: "999",
    offset: "-1",
    priority: "urgent",
    sort: "unknown",
    status: "todo",
  })

  assert.deepEqual(state, defaultFindingsSearchState)
  assert.equal(findingsSearchQueryString(state), "")
})

test("findings search state serializes only shareable non-default params", () => {
  const state = parseFindingsSearch({
    assetId: "asset-1",
    assetKey: "payments-api",
    cvssMin: "7.5",
    direction: "desc",
    epssMax: "0.9",
    exposure: "internet-facing",
    kev: "true",
    limit: "25",
    offset: "50",
    ownerService: "platform",
    priority: "critical",
    sort: "score",
    status: "open",
  })

  assert.deepEqual(definedSearch(findingsSearchToUrlSearch(state)), {
    assetId: "asset-1",
    assetKey: "payments-api",
    ownerService: "platform",
    priority: "critical",
    status: "open",
    kev: "true",
    exposure: "internet-facing",
    epssMax: "0.9",
    cvssMin: "7.5",
    sort: "score",
    direction: "desc",
    limit: 25,
    offset: 50,
  })
  assert.equal(
    findingsSearchQueryString(state),
    "assetId=asset-1&assetKey=payments-api&cvssMin=7.5&direction=desc&epssMax=0.9&exposure=internet-facing&kev=true&limit=25&offset=50&ownerService=platform&priority=critical&sort=score&status=open",
  )
})

test("findings search maps URL state to generated findings API params", () => {
  const state = parseFindingsSearch({
    assetId: "asset-1",
    cvssMax: "9.8",
    cvssMin: "4",
    direction: "desc",
    epssMin: "0.7",
    kev: "false",
    ownerService: "payments",
    priority: "high",
    sort: "epss",
  })

  assert.deepEqual(findingsSearchToFilters(state), {
    cvssMax: "9.8",
    cvssMin: "4",
    epssMax: "",
    epssMin: "0.7",
    exposure: "",
    kev: "false",
    ownerService: "payments",
    priority: "high",
    status: "",
  })
  assert.deepEqual(findingsSearchToApiParams(state, "project-1"), {
    asset_id: "asset-1",
    cvss_max: 9.8,
    cvss_min: 4,
    direction: "desc",
    epss_max: undefined,
    epss_min: 0.7,
    exposure: undefined,
    kev: false,
    limit: 10,
    offset: 0,
    owner_service: "payments",
    priority: "high",
    project_id: "project-1",
    sort: "epss",
    status: undefined,
  })
})

test("findings search drops invalid max range values that are below min", () => {
  const state = parseFindingsSearch({
    cvssMax: "4",
    cvssMin: "9",
    epssMax: "0.2",
    epssMin: "0.7",
  })

  assert.equal(state.cvssMin, "9")
  assert.equal(state.cvssMax, "")
  assert.equal(state.epssMin, "0.7")
  assert.equal(state.epssMax, "")
  assert.deepEqual(findingsSearchToApiParams(state, "project-1"), {
    asset_id: undefined,
    cvss_max: undefined,
    cvss_min: 9,
    direction: "asc",
    epss_max: undefined,
    epss_min: 0.7,
    exposure: undefined,
    kev: undefined,
    limit: 10,
    offset: 0,
    owner_service: undefined,
    priority: undefined,
    project_id: "project-1",
    sort: "operational",
    status: undefined,
  })
})

test("findings search updates reset paging except explicit page movement", () => {
  const state = parseFindingsSearch({
    limit: "25",
    offset: "50",
    priority: "critical",
  })

  assert.equal(updateFindingsSearch(state, { status: "open" }).offset, 0)
  assert.equal(
    updateFindingsSearch(state, { offset: 75 }, { resetOffset: false }).offset,
    75,
  )
  assert.deepEqual(clearFindingsFilters(state), {
    ...defaultFindingsSearchState,
    limit: 25,
    sort: "operational",
  })
})

test("findings search cleanup preserves route-owned project id", () => {
  assert.equal(
    cleanFindingsSearchQueryString(
      "projectId=project-1&status=open&unknown=drop&limit=999",
    ),
    "status=open&projectId=project-1",
  )
})
