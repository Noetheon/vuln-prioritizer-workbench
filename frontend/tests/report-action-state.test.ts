import assert from "node:assert/strict"
import test from "node:test"

import { reportActionsAvailable } from "../src/workbench/report-action-state.ts"

const completedRun = { status: "succeeded" } as never
const failedRun = { status: "failed" } as never

test("report actions require a completed selected run on the reports route", () => {
  assert.equal(
    reportActionsAvailable({
      currentPath: "/reports",
      reportActionPending: false,
      reportsLoading: false,
      selectedReportRun: completedRun,
    }),
    true,
  )
  assert.equal(
    reportActionsAvailable({
      currentPath: "/imports",
      reportActionPending: false,
      reportsLoading: false,
      selectedReportRun: completedRun,
    }),
    false,
  )
  assert.equal(
    reportActionsAvailable({
      currentPath: "/reports",
      reportActionPending: false,
      reportsLoading: false,
      selectedReportRun: null,
    }),
    false,
  )
  assert.equal(
    reportActionsAvailable({
      currentPath: "/reports",
      reportActionPending: false,
      reportsLoading: false,
      selectedReportRun: failedRun,
    }),
    false,
  )
})

test("report actions stay disabled while reports load or generation is pending", () => {
  assert.equal(
    reportActionsAvailable({
      currentPath: "/reports",
      reportActionPending: false,
      reportsLoading: true,
      selectedReportRun: completedRun,
    }),
    false,
  )
  assert.equal(
    reportActionsAvailable({
      currentPath: "/reports",
      reportActionPending: true,
      reportsLoading: false,
      selectedReportRun: completedRun,
    }),
    false,
  )
})
