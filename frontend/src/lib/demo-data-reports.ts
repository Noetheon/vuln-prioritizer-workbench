import { DEMO_PROJECT_ID } from "./demo-data-project.ts"

const createdAt = "2026-04-29T12:13:00Z"
const demoChecksum = "demo-only-not-a-real-checksum"

const reportRows = [
  ["001", "technical-report.md", "markdown", "text/markdown", 28940],
  ["002", "executive-report.html", "html", "text/html", 64200],
  ["003", "analysis-result.v1.json", "json", "application/json", 117280],
  ["004", "findings.csv", "csv", "text/csv", 11880],
  ["005", "results.sarif", "sarif", "application/sarif+json", 44420],
  ["006", "attack-navigator-layer.json", "attack-navigator", "application/json", 7820],
  ["007", "evidence-bundle.zip", "zip", "application/zip", 236900],
] as const

export const DEMO_REPORTS = reportRows.map(
  ([id, filename, format, contentType, sizeBytes]) => ({
    id: `__demo__report-${id}`,
    analysis_run_id: "demo-run-0001",
    content_type: contentType,
    created_at: createdAt,
    download_url: "#demo-download",
    filename,
    format,
    kind: format === "zip" ? "bundle" : "report",
    metadata_json: {
      demo_preview: true,
      note: "Demo preview row; persisted demo workspace downloads real artifacts.",
    },
    project_id: DEMO_PROJECT_ID,
    sha256: `${demoChecksum}:${filename}`,
    size_bytes: sizeBytes,
  }),
)
