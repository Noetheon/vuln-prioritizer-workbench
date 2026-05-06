import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
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
import { workbenchQueryKeys } from "./workbench-query-keys"

type UseReportsRouteStateOptions = {
  currentPath: WorkbenchPath
  onAuthExpired: () => Promise<void>
  selectedReportRun: AnalysisRunPublic | null
  selectedRunId: string
}

async function downloadReportArtifact(report: ReportPublic) {
  const request = reportDownloadRequest(report, getAccessToken(), OpenAPI.BASE)
  const response = await fetch(request.url, {
    credentials: request.credentials,
    headers: request.headers,
  })
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
  const queryClient = useQueryClient()
  const [verificationReport, setVerificationReport] =
    useState<ReportVerificationPublic | null>(null)
  const [verificationReportTarget, setVerificationReportTarget] =
    useState<ReportPublic | null>(null)
  const [verificationLoading, setVerificationLoading] = useState(false)
  const [reportActionMessage, setReportActionMessage] = useState("")
  const [reportActionError, setReportActionError] = useState("")
  const [activeReportFormat, setActiveReportFormat] = useState<
    TemplateReportFormat | ""
  >("")
  const reportsQuery = useQuery({
    enabled: currentPath === "/reports" && Boolean(selectedRunId),
    queryFn: () => ReportsService.readRunReports({ run_id: selectedRunId }),
    queryKey: workbenchQueryKeys.reports(selectedRunId),
    retry: false,
    staleTime: 15_000,
  })
  const createReportMutation = useMutation({
    mutationFn: (format: TemplateReportFormat) =>
      ReportsService.createRunReport({
        run_id: selectedRunId,
        reportCreate: { format },
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: workbenchQueryKeys.reports(selectedRunId),
      })
    },
  })
  const verifyReportMutation = useMutation({
    mutationFn: (report: ReportPublic) =>
      ReportsService.verifyReport({ report_id: report.id }),
  })
  const reports = reportsQuery.data?.data ?? []
  const reportsLoading = reportsQuery.isLoading || reportsQuery.isFetching
  const reportsError = reportsQuery.isError
    ? apiErrorMessage("Report history unavailable", reportsQuery.error)
    : ""
  const reportActionsEnabled =
    currentPath === "/reports" &&
    Boolean(selectedReportRun) &&
    isReportableRunStatus(selectedReportRun?.status) &&
    !reportsLoading

  useEffect(() => {
    if (currentPath === "/reports" && selectedRunId) {
      setVerificationReport(null)
      setVerificationReportTarget(null)
      setVerificationLoading(false)
      return
    }
    setVerificationReport(null)
    setVerificationReportTarget(null)
    setVerificationLoading(false)
  }, [currentPath, selectedRunId])

  useEffect(() => {
    if (
      reportsQuery.error instanceof ApiError &&
      [401, 403].includes(reportsQuery.error.status)
    ) {
      void onAuthExpired()
    }
  }, [onAuthExpired, reportsQuery.error])

  function refreshReports() {
    void queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.reports(selectedRunId),
    })
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
      const report = await createReportMutation.mutateAsync(format)
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
      const verification = await verifyReportMutation.mutateAsync(report)
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
    verificationLoading,
    verificationReport,
    verificationReportTarget,
    verifyEvidenceReport,
  }
}
