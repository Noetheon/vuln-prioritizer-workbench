import assert from "node:assert/strict"
import test from "node:test"
import { sbomAssessmentOutcome } from "../src/components/imports/sbom-assessment-model.ts"

test("a partial zero-match assessment never claims a completed clean scan", () => {
  const outcome = sbomAssessmentOutcome({
    status: "partial",
    scanner_match_count: 0,
    prioritized_match_count: 0,
  })
  assert.equal(outcome.tone, "warning")
  assert.match(outcome.title, /partial/)
})

test("a complete zero-match scan describes the evidence boundary", () => {
  const outcome = sbomAssessmentOutcome({
    status: "complete",
    scanner_match_count: 0,
    prioritized_match_count: 0,
  })
  assert.equal(outcome.tone, "success")
  assert.match(outcome.title, /no matches/)
  assert.match(outcome.description, /does not prove/)
})

test("scanner matches without prioritized CVEs remain visible", () => {
  const unassigned = sbomAssessmentOutcome({
    status: "complete",
    scanner_match_count: 2,
    prioritized_match_count: 0,
  })
  assert.match(unassigned.description, /none could be passed/)
  const assigned = sbomAssessmentOutcome({
    status: "complete",
    scanner_match_count: 2,
    prioritized_match_count: 2,
  })
  assert.match(assigned.description, /passed to prioritization/)
})
