import assert from "node:assert/strict"
import test from "node:test"

import { ApiError } from "../src/lib/api-client-errors.ts"
import { decisionRefreshPollingInterval, millisecondsUntilUtcDayChange } from "../src/lib/decision-freshness.ts"
import { readProjectSummariesWithLimit } from "../src/workbench/workbench-query-model.ts"

test("pending governance refresh is visible and retried without retrying unrelated errors", () => {
  const error = new ApiError(503, {
    detail: {
      code: "decision_refresh_pending",
      message: "Current decisions are awaiting today's governance update.",
    },
  })
  assert.equal(decisionRefreshPollingInterval(error), 2000)
  assert.equal(decisionRefreshPollingInterval(new ApiError(503, { detail: "Other outage" })), false)
  assert.equal(decisionRefreshPollingInterval(new ApiError(404, error.body)), false)
  assert.equal(decisionRefreshPollingInterval(new Error("network")), false)
  assert.equal(decisionRefreshPollingInterval(null), false)
  assert.equal(decisionRefreshPollingInterval(new ApiError(503, null)), false)
  assert.equal(decisionRefreshPollingInterval(new ApiError(503, {})), false)
})

test("project overview retries only a summary awaiting governance maintenance", async () => {
  const pending = new ApiError(503, { detail: { code: "decision_refresh_pending" } })
  const result = await readProjectSummariesWithLimit(
    ["pending", "failed"],
    new AbortController().signal,
    async ({ project_id }) => {
      throw project_id === "pending" ? pending : new ApiError(500, {})
    },
  )
  assert.deepEqual(result.refreshPendingProjectIds, ["pending"])
  assert.deepEqual(result.failedProjectIds.sort(), ["failed", "pending"])
})

test("an open view refreshes at the next UTC day, including the year boundary", () => {
  assert.equal(millisecondsUntilUtcDayChange(new Date("2026-09-23T23:59:58Z")), 2100)
  assert.equal(millisecondsUntilUtcDayChange(new Date("2026-12-31T23:59:59Z")), 1100)
  assert.equal(millisecondsUntilUtcDayChange(new Date("2026-09-23T00:00:00Z")), 86_400_100)
})
