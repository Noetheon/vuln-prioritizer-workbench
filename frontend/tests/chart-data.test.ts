import assert from "node:assert/strict"
import test from "node:test"

import {
  epssBucketChartData,
  findingsByPriorityChartData,
  priorityCount,
  runActivityTrendData,
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

test("normalizes API priority casing for dashboard counts", () => {
  const summary = {
    counts_by_priority: {
      critical: 3,
      High: 2,
    },
  } as SummaryFixture

  assert.equal(priorityCount(summary, "Critical"), 3)
  assert.equal(priorityCount(summary, "High"), 2)
  assert.deepEqual(
    findingsByPriorityChartData(summary)
      .slice(0, 2)
      .map((item) => [item.label, item.value]),
    [
      ["Critical", 3],
      ["High", 2],
    ],
  )
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

test("builds run activity trends from the latest limited runs", () => {
  const data = runActivityTrendData(
    [
      {
        started_at: "2026-01-03T08:00:00Z",
        status: "completed",
      },
      {
        started_at: "2026-01-02T08:00:00Z",
        status: "failed",
      },
      {
        started_at: "2026-01-01T08:00:00Z",
        status: "completed",
      },
    ],
    2,
  )

  assert.deepEqual(
    data.map((item) => [item.detail, item.tone, item.value]),
    [
      ["failed", "failed", 1],
      ["completed", "completed", 2],
    ],
  )
  assert.notEqual(data[0].label, "Run 1")
})

test("uses pending fallback labels for runs without start timestamps", () => {
  const data = runActivityTrendData([{}], 1)

  assert.deepEqual(data, [
    {
      detail: "pending",
      label: "Run 1",
      tone: "pending",
      value: 1,
    },
  ])
})

test("normalizes partial EPSS bucket counts into chart buckets", () => {
  const data = epssBucketChartData({
    critical: 1,
    medium: 3,
  })

  assert.deepEqual(
    data.map((item) => [item.label, item.detail, item.value, item.tone]),
    [
      ["Low Exposure", "0.00 – 0.25", 0, "low"],
      ["Medium Exposure", "0.25 – 0.50", 3, "medium"],
      ["High Exposure", "0.50 – 0.70", 0, "high"],
      ["Critical Exposure", "≥ 0.70", 1, "critical"],
    ],
  )
})
