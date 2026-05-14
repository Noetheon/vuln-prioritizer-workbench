import type { ReportPublic } from "../api-client"

export type ReportDownloadArtifact = {
  blob: Blob
  filename: string
}

type ReportDownloadDocument = Pick<Document, "createElement"> & {
  body: Pick<HTMLElement, "append">
}
type ReportDownloadTimer = (handler: () => void, delayMs: number) => unknown
type ReportDownloadUrlApi = Pick<
  typeof URL,
  "createObjectURL" | "revokeObjectURL"
>

export type StartReportDownloadOptions = {
  document?: ReportDownloadDocument
  revokeDelayMs?: number
  setTimeout?: ReportDownloadTimer
  urlApi?: ReportDownloadUrlApi
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

export const REPORT_OBJECT_URL_REVOKE_DELAY_MS = 1_000

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

export function startReportDownload(
  { blob, filename }: ReportDownloadArtifact,
  options: StartReportDownloadOptions = {},
): void {
  const ownerDocument = options.document ?? document
  const setTimer = options.setTimeout ?? globalThis.setTimeout
  const urlApi = options.urlApi ?? URL
  const objectUrl = urlApi.createObjectURL(blob)
  const anchor = ownerDocument.createElement("a")

  anchor.href = objectUrl
  anchor.download = filename
  ownerDocument.body.append(anchor)
  try {
    anchor.click()
  } finally {
    anchor.remove()
    setTimer(() => {
      urlApi.revokeObjectURL(objectUrl)
    }, options.revokeDelayMs ?? REPORT_OBJECT_URL_REVOKE_DELAY_MS)
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
