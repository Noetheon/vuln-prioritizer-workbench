import assert from "node:assert/strict"
import test from "node:test"

import { defaultFindingsSearchState } from "../src/components/findings/findings-search-types.ts"
import { findingsSearchForSavedView } from "../src/components/findings/findings-view-state.ts"

const openCritical = {
  ...defaultFindingsSearchState,
  offset: 50,
  ownerService: "payments",
  priority: "critical" as const,
  query: "log4j",
  status: "open" as const,
}

test("a view keeps the filters the reader chose", () => {
  const overdue = findingsSearchForSavedView(openCritical, "overdue")

  assert.equal(overdue.sla, "overdue")
  assert.equal(overdue.priority, "critical")
  assert.equal(overdue.status, "open")
  assert.equal(overdue.query, "log4j")
  assert.equal(overdue.ownerService, "payments")
  assert.equal(overdue.offset, 0)
  assert.equal(overdue.sort, "priority")
  assert.equal(overdue.direction, "asc")
})

test("a view replaces the condition of the previous view", () => {
  const kev = findingsSearchForSavedView(
    { ...openCritical, exposure: "internet-facing", sla: "overdue" },
    "kev",
  )

  assert.equal(kev.kev, "true")
  assert.equal(kev.sla, "")
  assert.equal(kev.exposure, "")
  assert.equal(kev.sort, "kev")
  assert.equal(kev.direction, "desc")

  const internet = findingsSearchForSavedView(kev, "internet")
  assert.equal(internet.exposure, "internet-facing")
  assert.equal(internet.kev, "")
})

test("closed statuses belong to their views", () => {
  const accepted = findingsSearchForSavedView(openCritical, "accepted")
  assert.equal(accepted.status, "accepted")
  assert.equal(accepted.sort, "last_seen")
  assert.equal(accepted.priority, "critical")

  const fixed = findingsSearchForSavedView(accepted, "fixed")
  assert.equal(fixed.status, "fixed")

  // Overdue, KEV, and the other views return from a closed status to open work.
  assert.equal(findingsSearchForSavedView(fixed, "overdue").status, "")
  assert.equal(
    findingsSearchForSavedView({ ...openCritical, status: "all" }, "kev").status,
    "",
  )
  assert.equal(
    findingsSearchForSavedView({ ...openCritical, status: "in_review" }, "kev")
      .status,
    "in_review",
  )
})

test("immediate work and open work set their own scope", () => {
  const immediate = findingsSearchForSavedView(
    { ...defaultFindingsSearchState, status: "remediating" },
    "immediate",
  )
  assert.equal(immediate.priority, "critical")
  assert.equal(immediate.status, "open")

  const openWork = findingsSearchForSavedView(immediate, "all")
  assert.equal(openWork.status, "")
  assert.equal(openWork.priority, "critical")
  assert.equal(openWork.sort, defaultFindingsSearchState.sort)

  const custom = findingsSearchForSavedView(
    { ...openCritical, kev: "true" },
    "custom",
  )
  assert.equal(custom.kev, "")
  assert.equal(custom.status, "open")
})
