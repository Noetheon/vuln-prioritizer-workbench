import assert from "node:assert/strict"
import test from "node:test"

import {
  formatReportDateTime,
  isReportableRunStatus,
  reportFormatLabel,
  reportSizeLabel,
  type ReportFormat,
} from "../src/lib/report-format.ts"

test("report format labels cover every supported format", () => {
  const expectedLabels: Record<ReportFormat, string> = {
    "attack-navigator": "ATT&CK Navigator",
    csv: "CSV",
    html: "HTML",
    json: "JSON",
    markdown: "MARKDOWN",
    sarif: "SARIF",
    zip: "Evidence ZIP",
  }

  for (const [format, label] of Object.entries(expectedLabels)) {
    assert.equal(reportFormatLabel(format), label)
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

test("reportable run statuses are limited to completed states", () => {
  for (const status of ["succeeded", "completed", "completed_with_errors"]) {
    assert.equal(isReportableRunStatus(status), true)
  }
  for (const status of [
    null,
    undefined,
    "",
    "pending",
    "running",
    "failed",
    "cancelled",
  ]) {
    assert.equal(isReportableRunStatus(status), false)
  }
})
