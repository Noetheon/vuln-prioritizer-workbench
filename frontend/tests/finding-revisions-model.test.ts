import assert from "node:assert/strict"
import test from "node:test"
import type { DecisionRevisionPublic } from "../src/api-client"
import { revisionDifferenceRows } from "../src/components/finding-detail/finding-revisions-model.ts"

test("revision comparison distinguishes a changed decision from a later observation timestamp", () => {
  const before = {
    priority: "High",
    status: "open",
    risk_score: 50,
    rationale: "Initial evidence",
    provider_snapshot_id: "old",
    observed_at: "2026-01-01",
  } as DecisionRevisionPublic
  const after = {
    ...before,
    risk_score: 80,
    provider_snapshot_id: "new",
    observed_at: "2026-01-02",
  }
  assert.deepEqual(revisionDifferenceRows(after, before), [
    { field: "risk_score", label: "Risk score", before: "50", after: "80" },
    {
      field: "provider_snapshot_id",
      label: "Provider snapshot",
      before: "old",
      after: "new",
    },
  ])
  assert.deepEqual(
    revisionDifferenceRows({ ...before, observed_at: "2026-01-03" }, before),
    [],
  )
})

test("the first legacy revision does not imply a fabricated prior state", () => {
  const revision = {
    priority: "Critical",
    risk_score: null,
  } as DecisionRevisionPublic
  assert.deepEqual(revisionDifferenceRows(revision), [])
  assert.deepEqual(
    revisionDifferenceRows({ ...revision, risk_score: 0 }, revision),
    [
      {
        field: "risk_score",
        label: "Risk score",
        before: "Not recorded",
        after: "0",
      },
    ],
  )
})
