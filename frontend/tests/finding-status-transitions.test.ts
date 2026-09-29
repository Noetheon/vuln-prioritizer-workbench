import assert from "node:assert/strict"
import test from "node:test"
import {
  isManualStatus,
  lifecycleSourceLabel,
  manualStatusLabel,
  manualStatusOptions,
  statusReasonError,
  statusRequiresReason,
  statusUpdateRequest,
} from "../src/lib/finding-status-transitions.ts"

test("analysts may set workflow and closure statuses but not governed ones", () => {
  assert.deepEqual(
    manualStatusOptions.map((option) => option.value),
    ["open", "in_review", "remediating", "resolved", "false_positive"],
  )
  assert.equal(isManualStatus("resolved"), true)
  assert.equal(isManualStatus("fixed"), false)
  assert.equal(isManualStatus("accepted"), false)
  assert.equal(isManualStatus(undefined), false)
})

test("closing a finding requires a bounded reason", () => {
  assert.equal(statusRequiresReason("resolved"), true)
  assert.equal(statusRequiresReason("false_positive"), true)
  assert.equal(statusRequiresReason("in_review"), false)
  assert.equal(
    statusReasonError("false_positive", "  "),
    "Describe why this finding is false positive.",
  )
  assert.equal(statusReasonError("resolved", "Patched in 2.17.1"), "")
  assert.equal(statusReasonError("open", ""), "")
  assert.match(statusReasonError("resolved", "x".repeat(2001)), /under 2000/)
})

test("status requests send a trimmed reason only when one was given", () => {
  assert.deepEqual(statusUpdateRequest("open", "  "), { status: "open" })
  assert.deepEqual(statusUpdateRequest("resolved", " Patched "), {
    status: "resolved",
    reason: "Patched",
  })
  assert.equal(manualStatusLabel("in_review"), "In review")
})

test("lifecycle sources read as plain language", () => {
  assert.equal(
    lifecycleSourceLabel("import_not_observed"),
    "Not reported by a rescan",
  )
  assert.equal(lifecycleSourceLabel("manual"), "Changed by analyst")
  assert.equal(lifecycleSourceLabel("future_source"), "future source")
})
