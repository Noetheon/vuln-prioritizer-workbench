import assert from "node:assert/strict"
import test from "node:test"

import {
  formatReportDateTime,
  isReportableRunStatus,
  reportFormatLabel,
  reportSizeLabel,
  type ReportFormat,
} from "../src/lib/report-format.ts"
import {
  AnalysisRunStatusSchema,
  ReportCreateSchema,
} from "../src/client/schemas.gen.ts"

test("report format labels cover every backend-supported format", () => {
  const expectedLabels: Record<ReportFormat, string> = {
    markdown: "MARKDOWN",
    html: "HTML",
    json: "JSON",
    csv: "CSV",
    zip: "Evidence ZIP",
    "attack-navigator": "ATT&CK Navigator",
    sarif: "SARIF",
  }
  const backendFormats = [...ReportCreateSchema.properties.format.enum]

  assert.deepEqual(backendFormats, Object.keys(expectedLabels))

  for (const format of backendFormats) {
    assert.equal(reportFormatLabel(format), expectedLabels[format])
  }
})

test("report size labels handle byte, kilobyte, and megabyte boundaries", () => {
  assert.equal(reportSizeLabel(0), "0 B")
  assert.equal(reportSizeLabel(1023), "1023 B")
  assert.equal(reportSizeLabel(1024), "1.0 KB")
  assert.equal(reportSizeLabel(1536), "1.5 KB")
  assert.equal(reportSizeLabel(1024 * 1024 - 1), "1024.0 KB")
  assert.equal(reportSizeLabel(1024 * 1024), "1.0 MB")
})

test("report date labels hide missing and invalid timestamps", () => {
  assert.equal(formatReportDateTime(null), "Not recorded")
  assert.equal(formatReportDateTime(undefined), "Not recorded")
  assert.equal(formatReportDateTime("not-a-date"), "Not recorded")
  assert.notEqual(formatReportDateTime("2026-05-15T10:00:00Z"), "Not recorded")
})

test("reportable run statuses are limited to backend completed states", () => {
  const reportableStatuses = new Set([
    "succeeded",
    "completed",
    "completed_with_errors",
  ])

  for (const status of AnalysisRunStatusSchema.enum) {
    assert.equal(isReportableRunStatus(status), reportableStatuses.has(status))
  }

  assert.equal(isReportableRunStatus(null), false)
  assert.equal(isReportableRunStatus(undefined), false)
  assert.equal(isReportableRunStatus(""), false)
})
