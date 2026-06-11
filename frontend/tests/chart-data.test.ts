import assert from "node:assert/strict"
import test from "node:test"

import {
  epssBucketChartData,
  findingsByPriorityChartData,
  mitigationLeverChartData,
  priorityCount,
  riskAverageTrendData,
  riskScoreBand,
  runActivityTrendData,
  topServicesByRiskChartData,
} from "../src/lib/chart-data.ts"
import type {
  AnalysisRunPublic,
  MitigationLeverPublic,
  ProjectDecisionSummaryPublic,
  RiskTrendPointPublic,
} from "../src/api-client"

function summaryFixture(
  value: Partial<ProjectDecisionSummaryPublic>,
): ProjectDecisionSummaryPublic {
  return value as unknown as ProjectDecisionSummaryPublic
}

function runFixture(value: Partial<AnalysisRunPublic>): AnalysisRunPublic {
  return value as unknown as AnalysisRunPublic
}

function trendPointFixture(
  value: Partial<RiskTrendPointPublic>,
): RiskTrendPointPublic {
  return value as unknown as RiskTrendPointPublic
}

function leverFixture(
  value: Partial<MitigationLeverPublic>,
): MitigationLeverPublic {
  return value as unknown as MitigationLeverPublic
}

test("keeps priority chart additive when lifecycle states are present", () => {
  const data = findingsByPriorityChartData(
    summaryFixture({
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
    }),
  )

  assert.deepEqual(
    data.map((item) => [item.label, item.value]),
    [
      ["Critical", 2],
      ["High", 1],
      ["Medium", 0],
      ["Low", 3],
    ],
  )
  assert.equal(
    data.reduce((total, item) => total + item.value, 0),
    6,
  )
})

test("keeps base priority buckets when lifecycle states are zero", () => {
  const data = findingsByPriorityChartData(
    summaryFixture({
      counts_by_priority: {
        Critical: 1,
      },
      counts_by_status: {
        accepted: 0,
      },
    }),
  )

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
  const summary = summaryFixture({
    counts_by_priority: {
      critical: 3,
      High: 2,
    },
  })

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
  assert.equal(data[0].tone, "critical")
})

test("builds run activity trends from the latest limited runs", () => {
  const data = runActivityTrendData(
    [
      runFixture({
        started_at: "2026-01-03T08:00:00Z",
        status: "completed",
      }),
      runFixture({
        started_at: "2026-01-02T08:00:00Z",
        status: "failed",
      }),
      runFixture({
        started_at: "2026-01-01T08:00:00Z",
        status: "completed",
      }),
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
  const data = runActivityTrendData([runFixture({})], 1)

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

test("maps risk scores to severity bands at the operational thresholds", () => {
  assert.equal(riskScoreBand(0), "low")
  assert.equal(riskScoreBand(29.9), "low")
  assert.equal(riskScoreBand(30), "medium")
  assert.equal(riskScoreBand(49.9), "medium")
  assert.equal(riskScoreBand(50), "high")
  assert.equal(riskScoreBand(69.9), "high")
  assert.equal(riskScoreBand(70), "critical")
  assert.equal(riskScoreBand(100), "critical")
})

test("keeps risk trend points oldest-first and slices to the latest runs", () => {
  const data = riskAverageTrendData(
    [
      trendPointFixture({
        average_risk_score: 80.5,
        kev_count: 1,
        max_risk_score: 95,
        open_finding_count: 4,
        started_at: "2026-06-01T10:00:00Z",
      }),
      trendPointFixture({
        average_risk_score: 41.2,
        kev_count: 0,
        max_risk_score: 60,
        open_finding_count: 2,
        started_at: "2026-06-05T10:00:00Z",
      }),
      trendPointFixture({
        average_risk_score: null,
        open_finding_count: 0,
        started_at: "2026-06-09T10:00:00Z",
      }),
    ],
    2,
  )

  assert.equal(data.length, 2)
  assert.deepEqual(
    data.map((item) => [item.value, item.tone, item.detail]),
    [
      [41.2, "medium", "2 open · max 60 · 0 KEV"],
      [0, "standard", "No open findings"],
    ],
  )
})

test("maps mitigation levers with projection details", () => {
  const data = mitigationLeverChartData([
    leverFixture({
      action_label: "Upgrade log4j-core 2.14.1 to 2.17.2",
      average_delta: 13.3,
      projected_average_risk_score: 20,
      resolved_finding_count: 2,
      resolved_kev_count: 1,
      risk_score_sum: 80,
    }),
    leverFixture({
      action_label: "Remediate CVE-2024-0001",
      average_delta: null,
      projected_average_risk_score: null,
      resolved_finding_count: 1,
      resolved_kev_count: 0,
      risk_score_sum: 20,
    }),
  ])

  assert.deepEqual(
    data.map((item) => [item.label, item.value, item.tone, item.detail]),
    [
      [
        "Upgrade log4j-core 2.14.1 to 2.17.2",
        80,
        "medium",
        "Resolves 2 findings (1 KEV) · projected avg 20 (−13.3 avg)",
      ],
      [
        "Remediate CVE-2024-0001",
        20,
        "low",
        "Resolves 1 finding · clears all open findings",
      ],
    ],
  )
})

test("omits near-zero average projections from lever details", () => {
  const data = mitigationLeverChartData([
    leverFixture({
      action_label: "Upgrade nginx 1.25.1 to 1.25.3",
      average_delta: -0.1,
      projected_average_risk_score: 99.6,
      resolved_finding_count: 1,
      resolved_kev_count: 1,
      risk_score_sum: 100,
    }),
  ])

  assert.equal(data[0].detail, "Resolves 1 finding (1 KEV)")
})
