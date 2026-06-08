import assert from "node:assert/strict"
import test from "node:test"

import {
  compareReportsByNewest,
  compareReportsForDisplay,
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
import type { ReportFormatCapabilityPublic } from "../src/api-client"
import {
  additionalArtifactCards,
  artifactCardForFormat,
  artifactCardsFromCapabilities,
  recommendedArtifactCards,
  requireArtifactCardForFormat,
} from "../src/lib/report-capability-catalog.ts"

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

test("report action cards derive runtime metadata from capabilities", () => {
  const capabilities: ReportFormatCapabilityPublic[] = [
    {
      action_label: "Build evidence ZIP",
      audience: "Audit",
      content_type: "application/zip",
      detail: "ZIP package with manifest and hashes.",
      filename: "evidence-bundle.zip",
      format: "zip",
      kind: "evidence-bundle",
      label: "Evidence ZIP",
      title: "Evidence ZIP Bundle",
    },
    {
      action_label: "Generate Executive HTML",
      audience: "Executive",
      content_type: "text/html",
      detail: "HTML report for decision review.",
      filename: "executive-report.html",
      format: "html",
      kind: "executive-report",
      label: "HTML",
      title: "Executive HTML",
    },
    {
      action_label: "Export CSV",
      audience: "Operations",
      content_type: "text/csv",
      detail: "CSV export for downstream tooling.",
      filename: "findings.csv",
      format: "csv",
      kind: "tabular-export",
      label: "CSV",
      title: "CSV Export",
    },
  ]

  const cards = artifactCardsFromCapabilities(capabilities)

  assert.equal(cards.length, 3)
  assert.equal(cards[0]?.reportFormat, "zip")
  assert.equal(cards[0]?.format, "Evidence ZIP")
  assert.equal(cards[0]?.title, "Evidence ZIP Bundle")
  assert.equal(cards[0]?.description, "ZIP package with manifest and hashes.")
  assert.equal(cards[0]?.filename, "evidence-bundle.zip")
  assert.equal(cards[0]?.kind, "evidence-bundle")
  assert.equal(cards[0]?.contentType, "application/zip")
  assert.deepEqual(
    recommendedArtifactCards(cards).map((card) => card.reportFormat),
    ["zip", "html"],
  )
  assert.deepEqual(
    additionalArtifactCards(cards).map((card) => card.reportFormat),
    ["csv"],
  )
  assert.equal(artifactCardForFormat(cards, "csv")?.title, "CSV Export")
  assert.equal(artifactCardForFormat(cards, "sarif"), null)
  assert.equal(
    requireArtifactCardForFormat(cards, "html").filename,
    "executive-report.html",
  )
  assert.throws(
    () => requireArtifactCardForFormat(cards, "sarif"),
    /Report format capability missing for sarif/,
  )
})

test("report size labels handle byte, kilobyte, and megabyte boundaries", () => {
  assert.equal(reportSizeLabel(0), "0 B")
  assert.equal(reportSizeLabel(1023), "1023 B")
  assert.equal(reportSizeLabel(1024), "1.0 KB")
  assert.equal(reportSizeLabel(1536), "1.5 KB")
  assert.equal(reportSizeLabel(1024 * 1024 - 1), "1024.0 KB")
  assert.equal(reportSizeLabel(1024 * 1024), "1.0 MB")
})

test("report display sorting uses deterministic format and created-at ties", () => {
  const reports = [
    reportFixture("report-csv", "csv", "same-time-c.csv", "2026-06-06T10:00:00Z"),
    reportFixture("report-zip-b", "zip", "same-time-b.zip", "2026-06-06T10:00:00Z"),
    reportFixture("report-html", "html", "same-time.html", "2026-06-06T10:00:00Z"),
    reportFixture("report-zip-a", "zip", "same-time-a.zip", "2026-06-06T10:00:00Z"),
    reportFixture("report-json", "json", "newer.json", "2026-06-06T10:05:00Z"),
  ]

  assert.deepEqual(
    reports.slice().sort(compareReportsForDisplay).map((report) => report.id),
    ["report-zip-a", "report-zip-b", "report-html", "report-csv", "report-json"],
  )
  assert.deepEqual(
    reports.slice().sort(compareReportsByNewest).map((report) => report.id),
    ["report-json", "report-zip-a", "report-zip-b", "report-html", "report-csv"],
  )
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

function reportFixture(
  id: string,
  format: ReportFormat,
  filename: string,
  createdAt: string,
) {
  return {
    created_at: createdAt,
    filename,
    format,
    id,
  }
}
