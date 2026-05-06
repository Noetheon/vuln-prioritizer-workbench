import type { ReportPublic } from "../api-client"

export function reportDownloadPath(report: Pick<ReportPublic, "id">): string {
  return `/api/v1/reports/${encodeURIComponent(report.id)}/download`
}

export function reportDownloadUrl(
  report: Pick<ReportPublic, "id">,
  baseUrl = "",
): string {
  const path = reportDownloadPath(report)
  const normalizedBaseUrl = baseUrl.trim().replace(/\/+$/, "")
  return normalizedBaseUrl ? `${normalizedBaseUrl}${path}` : path
}

export function reportDownloadHeaders(token = ""): HeadersInit | undefined {
  if (token) {
    const headers = new Headers()
    headers.set("Authorization", `Bearer ${token}`)
    return headers
  }
  return undefined
}

export function reportDownloadRequest(
  report: Pick<ReportPublic, "id">,
  token = "",
  baseUrl = "",
) {
  return {
    credentials: "include" as const,
    headers: reportDownloadHeaders(token),
    url: reportDownloadUrl(report, baseUrl),
  }
}
