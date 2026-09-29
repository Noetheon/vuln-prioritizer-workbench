import assert from "node:assert/strict"
import test from "node:test"
import {
  BULK_STATUS_MAX_FINDINGS,
  bulkStatusOutcomeMessage,
  selectAllState,
  selectedCountLabel,
  toggleAllSelection,
  toggleSelection,
  visibleSelection,
} from "../src/lib/finding-bulk-selection.ts"

test("selection only applies to findings still on screen, in screen order", () => {
  const selected = new Set(["b", "gone", "a"])
  assert.deepEqual(visibleSelection(selected, ["a", "b", "c"]), ["a", "b"])
  assert.deepEqual(visibleSelection(new Set(), ["a"]), [])
})

test("toggling rows and the page header builds new selections", () => {
  const start = new Set(["a"])
  const added = toggleSelection(start, "b", true)
  assert.deepEqual([...added], ["a", "b"])
  assert.deepEqual([...start], ["a"])
  assert.deepEqual([...toggleSelection(added, "a", false)], ["b"])
  assert.deepEqual([...toggleAllSelection(["a", "b"], true)], ["a", "b"])
  assert.deepEqual([...toggleAllSelection(["a", "b"], false)], [])
})

test("header checkbox reflects none, some, or all rows", () => {
  assert.equal(selectAllState(0, 5), false)
  assert.equal(selectAllState(0, 0), false)
  assert.equal(selectAllState(2, 5), "indeterminate")
  assert.equal(selectAllState(5, 5), true)
  assert.equal(selectedCountLabel(1), "1 finding selected")
  assert.equal(selectedCountLabel(3), "3 findings selected")
  assert.equal(BULK_STATUS_MAX_FINDINGS, 500)
})

test("bulk outcome summarises updates and distinct skip reasons", () => {
  assert.equal(
    bulkStatusOutcomeMessage({
      status: "resolved",
      updated_count: 2,
      updated_ids: ["a", "b"],
      skipped: [],
    }),
    "Marked 2 findings as resolved.",
  )
  assert.equal(
    bulkStatusOutcomeMessage({
      status: "in_review",
      updated_ids: ["a"],
    }),
    "Marked 1 finding as in review.",
  )
  const governed =
    "Finding is in governance-managed status 'accepted'; resolve the waiver or VEX statement instead."
  assert.equal(
    bulkStatusOutcomeMessage({
      status: "false_positive",
      updated_count: 0,
      skipped: [
        { finding_id: "a", detail: governed },
        { finding_id: "b", detail: governed },
      ],
    }),
    `No findings changed. 2 skipped: ${governed}`,
  )
  const message = bulkStatusOutcomeMessage({
    status: "open",
    updated_count: 1,
    skipped: [
      { finding_id: "a", detail: "One." },
      { finding_id: "b", detail: "Two." },
      { finding_id: "c", detail: "Three." },
    ],
  })
  assert.equal(
    message,
    "Marked 1 finding as open. 3 skipped: One. Two. (+1 more reasons)",
  )
})
