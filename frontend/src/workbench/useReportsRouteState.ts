import { useEffect, useState } from "react"

import {
  type AnalysisRunPublic,
  ApiError,
  OpenAPI,
  type ReportPublic,
  ReportsService,
  type ReportVerificationPublic,
} from "../api-client"
import { getAccessToken } from "../auth"
import type { WorkbenchPath } from "../components/app/AppShell"
import type { TemplateReportFormat } from "../lib/app-defaults"
import {
  apiErrorDetail,
  apiErrorMessage,
  objectRecord,
} from "../lib/app-errors"
import { isReportableRunStatus, reportFormatLabel } from "../lib/report-format"
import { reportDownloadRequest } from "./report-download"

type UseReportsRouteStateOptions = {
  currentPath: WorkbenchPath
  onAuthExpired: () => Promise<void>
  selectedReportRun: AnalysisRunPublic | null
  selectedRunId: string
}

async function downloadReportArtifact(report: ReportPublic) {
  const request = reportDownloadRequest(report, getAccessToken(), OpenAPI.BASE)
  const response = await fetch(request.url, { headers: request.headers })
  if (!response.ok) {
    let detail = ""
    try {
      detail = apiErrorDetail(await response.json()) ?? ""
    } catch {
      detail = ""
    }
    throw new Error(detail || `HTTP ${response.status}`)
  }
  const blob = await response.blob()
  const objectUrl = URL.createObjectURL(blob)
  const anchor = document.createElement("a")
  anchor.href = objectUrl
  anchor.download = report.filename
  document.body.append(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(objectUrl)
}

export function useReportsRouteState({
  currentPath,
  onAuthExpired,
  selectedReportRun,
  selectedRunId,
}: UseReportsRouteStateOptions) {
  const [reports, setReports] = useState<ReportPublic[]>([])
  const [reportsLoading, setReportsLoading] = useState(false)
  const [reportsError, setReportsError] = useState("")
  const [_verificationReport, setVerificationReport] =
    useState<ReportVerificationPublic | null>(null)
  const [_verificationReportTarget, setVerificationReportTarget] =
    useState<ReportPublic | null>(null)
  const [_verificationLoading, setVerificationLoading] = useState(false)
  const [reportActionMessage, setReportActionMessage] = useState("")
  const [reportActionError, setReportActionError] = useState("")
  const [activeReportFormat, setActiveReportFormat] = useState<
    TemplateReportFormat | ""
  >("")
  const [reportsReloadKey, setReportsReloadKey] = useState(0)
  const reportActionsEnabled =
    currentPath === "/reports" &&
    Boolean(selectedReportRun) &&
    isReportableRunStatus(selectedReportRun?.status) &&
    !reportsLoading

  useEffect(() => {
    let isMounted = true

    async function loadRunReports() {
      if (currentPath !== "/reports" || !selectedRunId) {
        setReports([])
        setReportsError("")
        setReportsLoading(false)
        setVerificationReport(null)
        setVerificationReportTarget(null)
        return
      }

      setReportsLoading(true)
      setReportsError("")
      setVerificationReport(null)
      setVerificationReportTarget(null)
      try {
        const reportPage = await ReportsService.readRunReports({
          run_id: selectedRunId,
        })
        if (isMounted) {
          setReports(reportPage.data)
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          await onAuthExpired()
          return
        }
        if (isMounted) {
          setReports([])
          setReportsError(apiErrorMessage("Report history unavailable", caught))
        }
      } finally {
        if (isMounted) {
          setReportsLoading(false)
        }
      }
    }

    void loadRunReports()
    return () => {
      isMounted = false
    }
  }, [currentPath, onAuthExpired, reportsReloadKey, selectedRunId])

  function refreshReports() {
    setReportsReloadKey((key) => key + 1)
  }

  async function createReport(format: TemplateReportFormat) {
    if (!selectedRunId) {
      setReportActionError(
        "Select a completed analysis run before generating reports.",
      )
      return
    }
    setReportActionError("")
    setReportActionMessage("")
    setActiveReportFormat(format)
    try {
      const report = await ReportsService.createRunReport({
        run_id: selectedRunId,
        reportCreate: { format },
      })
      setReports((currentReports) => [report, ...currentReports])
      setReportActionMessage(
        `${reportFormatLabel(report.format)} report generated as ${report.filename}.`,
      )
    } catch (caught) {
      setReportActionError(apiErrorMessage("Report generation failed", caught))
    } finally {
      setActiveReportFormat("")
    }
  }

  async function downloadReport(report: ReportPublic) {
    setReportActionError("")
    setReportActionMessage("")
    try {
      await downloadReportArtifact(report)
      setReportActionMessage(`Download started for ${report.filename}.`)
    } catch (caught) {
      setReportActionError(
        caught instanceof Error
          ? `Report download failed: ${caught.message}`
          : "Report download failed: unexpected client error",
      )
    }
  }

  async function verifyEvidenceReport(report: ReportPublic) {
    setVerificationLoading(true)
    setVerificationReport(null)
    setVerificationReportTarget(report)
    setReportActionError("")
    setReportActionMessage("")
    try {
      const verification = await ReportsService.verifyReport({
        report_id: report.id,
      })
      setVerificationReport(verification)
      const summary = objectRecord(verification.summary)
      setReportActionMessage(
        summary.ok
          ? `Evidence bundle verified: ${summary.verified_files ?? 0} files matched.`
          : `Evidence bundle verification failed: ${summary.modified_files ?? 0} modified, ${summary.missing_files ?? 0} missing.`,
      )
    } catch (caught) {
      setReportActionError(
        apiErrorMessage("Evidence verification failed", caught),
      )
      setVerificationReport(null)
      setVerificationReportTarget(null)
    } finally {
      setVerificationLoading(false)
    }
  }

  return {
    activeReportFormat,
    createReport,
    downloadReport,
    refreshReports,
    reportActionError,
    reportActionMessage,
    reportActionsEnabled,
    reports,
    reportsError,
    reportsLoading,
    verifyEvidenceReport,
  }
}
