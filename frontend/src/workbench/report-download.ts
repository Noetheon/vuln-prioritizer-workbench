import type { ReportPublic } from "../api-client"

export type ReportDownloadArtifact = {
  blob: Blob
  filename: string
}

type ReportDownloadResult = {
  data: Blob | File
  request: Request
  response: Response
}
type DownloadReportClient = (
  parameters: { report_id: string },
  options: { parseAs: "blob"; responseStyle: "fields" },
) => Promise<ReportDownloadResult>

let reportDownloadClient: DownloadReportClient | null = null

export function configureReportDownloadClient(
  client: DownloadReportClient | null,
): void {
  reportDownloadClient = client
}

export async function fetchReportDownload(
  report: Pick<ReportPublic, "filename" | "id">,
): Promise<ReportDownloadArtifact> {
  const downloadReport = reportDownloadClient ?? generatedDownloadReport
  const result = await downloadReport(
    { report_id: report.id },
    { parseAs: "blob", responseStyle: "fields" },
  )
  return {
    blob: result.data as Blob,
    filename:
      filenameFromContentDisposition(
        result.response.headers.get("content-disposition"),
      ) || report.filename,
  }
}

async function generatedDownloadReport(
  ...args: Parameters<DownloadReportClient>
): Promise<ReportDownloadResult> {
  const { ReportsService } = await import("../api-client")
  return ReportsService.downloadReport(...args) as unknown as ReportDownloadResult
}

function filenameFromContentDisposition(header: string | null): string {
  if (!header) {
    return ""
  }
  const encoded = /filename\*=UTF-8''([^;]+)/i.exec(header)?.[1]
  if (encoded) {
    try {
      return decodeURIComponent(encoded)
    } catch {
      return encoded
    }
  }
  const quoted = /filename="([^"]+)"/i.exec(header)?.[1]
  if (quoted) {
    return quoted
  }
  return /filename=([^;]+)/i.exec(header)?.[1]?.trim() ?? ""
}
