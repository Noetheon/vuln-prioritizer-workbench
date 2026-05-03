import assert from "node:assert/strict"
import test from "node:test"

import {
  findingsByPriorityChartData,
  topServicesByRiskChartData,
} from "../src/lib/chart-data.ts"

type SummaryFixture = {
  counts_by_priority?: Record<string, number>
  counts_by_status?: Record<string, number>
}

test("includes lifecycle states when present", () => {
  const data = findingsByPriorityChartData({
    counts_by_priority: {
      Critical: 2,
      High: 1,
      Medium: 0,
      Low: 3,
    },
    counts_by_status: {
      accepted: 4,
      suppressed: 1,
    },
  } as SummaryFixture)

  assert.deepEqual(
    data.map((item) => [item.label, item.value]),
    [
      ["Critical", 2],
      ["High", 1],
      ["Medium", 0],
      ["Low", 3],
      ["Accepted", 4],
      ["Suppressed", 1],
    ],
  )
})

test("keeps base priority buckets when lifecycle states are zero", () => {
  const data = findingsByPriorityChartData({
    counts_by_priority: {
      Critical: 1,
    },
    counts_by_status: {
      accepted: 0,
    },
  } as SummaryFixture)

  assert.deepEqual(
    data.map((item) => item.label),
    ["Critical", "High", "Medium", "Low"],
  )
  assert.deepEqual(
    data
      .filter((item) => ["High", "Medium", "Low"].includes(item.label))
      .map((item) => item.value),
    [0, 0, 0],
  )
})

test("returns zero-value priority buckets for null summary", () => {
  const data = findingsByPriorityChartData(null)

  assert.deepEqual(data, [
    { label: "Critical", tone: "critical", value: 0 },
    { label: "High", tone: "high", value: 0 },
    { label: "Medium", tone: "medium", value: 0 },
    { label: "Low", tone: "low", value: 0 },
  ])
})

test("adds highest priority to top service rollup detail", () => {
  const serviceData = [
    {
      dimension: "service",
      label: "billing-api",
      finding_count: 4,
      highest_priority: "Critical",
      risk_score_total: 21,
    },
  ]
  const data = topServicesByRiskChartData(serviceData, 10)
  assert.equal(data[0].detail, "4 findings · highest priority Critical")
})
