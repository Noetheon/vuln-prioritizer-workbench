import assert from "node:assert/strict"
import test from "node:test"
import type { FindingPublic } from "../src/api-client"
import { findingSlaLabel } from "../src/lib/finding-recorded-guidance.ts"

test("all finding surfaces use the recorded SLA including a custom policy", () => {
  assert.equal(
    findingSlaLabel({ sla: { label: "Custom policy", target_hours: 6 } }),
    "Custom policy · 6 hours",
  )
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
    "Emergency · 6 hours",
  )
  assert.equal(
    findingSlaLabel({
      evidence: {
        remediation: { sla: { label: "Scheduled", target_days: 3 } },
      },
    } as unknown as FindingPublic),
    "Scheduled · 3 days",
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

test("SLA targets read in days when they are whole days", () => {
  assert.equal(
    findingSlaLabel({ sla: { label: "Emergency", target_hours: 24 } }),
    "Emergency · 1 day",
  )
  assert.equal(
    findingSlaLabel({ sla: { label: "Standard", target_hours: 720 } }),
    "Standard · 30 days",
  )
  assert.equal(
    findingSlaLabel({ sla: { label: "Monitor", target_days: 1 } }),
    "Monitor · 1 day",
  )
  assert.equal(
    findingSlaLabel({ sla: { label: "Custom", target_hours: 1 } }),
    "Custom · 1 hour",
  )
  assert.equal(
    findingSlaLabel({ sla: { label: "Custom", target_hours: 36 } }),
    "Custom · 36 hours",
  )
})
