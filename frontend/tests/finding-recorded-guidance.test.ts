import assert from "node:assert/strict"
import test from "node:test"
import type { FindingPublic } from "../src/api-client"
import { findingSlaLabel } from "../src/lib/finding-recorded-guidance.ts"

test("all finding surfaces use the recorded SLA including a custom policy", () => {
  assert.equal(
    findingSlaLabel({
      evidence: { remediation: { sla: { label: " Within 6 hours " } } },
    } as unknown as FindingPublic),
    "Within 6 hours",
  )
  assert.equal(findingSlaLabel({}), "No SLA recorded")
  assert.equal(
    findingSlaLabel({
      evidence: {
        remediation: { sla: { label: "Emergency", target_hours: 6 } },
      },
    } as unknown as FindingPublic),
    "Emergency · 6h",
  )
  assert.equal(
    findingSlaLabel({
      evidence: {
        remediation: { sla: { label: "Scheduled", target_days: 3 } },
      },
    } as unknown as FindingPublic),
    "Scheduled · 3d",
  )
  assert.equal(
    findingSlaLabel({
      evidence: {
        remediation: {
          sla: {
            label: "Review",
            target_hours: Number.NaN,
            target_days: Number.NaN,
          },
        },
      },
    } as unknown as FindingPublic),
    "Review",
  )
  for (const label of [undefined, "", " ", 24, null]) {
    assert.equal(
      findingSlaLabel({
        evidence: { remediation: { sla: { label } } },
      } as unknown as FindingPublic),
      "No SLA recorded",
    )
  }
})
