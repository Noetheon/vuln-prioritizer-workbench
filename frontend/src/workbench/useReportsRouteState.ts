import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useEffect, useRef, useState } from "react"

import {
  type AnalysisRunPublic,
  OpenAPI,
  type ReportFormatCapabilityPublic,
  type ReportPublic,
  ReportsService,
  type ReportVerificationPublic,
  type WorkflowRunPublic,
  WorkflowsService,
} from "../api-client"
import { apiErrorMessage, objectRecord } from "../lib/app-errors"
import {
  reportFormatLabel,
  type ReportFormat,
} from "../lib/report-format"
import type { WorkbenchPath } from "../lib/workbench-navigation"
import { fetchReportDownload, startReportDownload } from "./report-download"
import { reportActionsAvailable } from "./report-action-state.ts"
import { reportsNeedPolling } from "./workbench-query-model"
import { workbenchQueryKeys } from "./workbench-query-keys"
import { workflowNeedsPolling, workflowStatusLabel } from "./workflow-model"
import { subscribeWorkflowUpdates } from "./workflow-stream"

type UseReportsRouteStateOptions = {
  currentPath: WorkbenchPath
  reportFormatCapabilities: readonly ReportFormatCapabilityPublic[]
  capabilitiesError: string
  selectedReportRun: AnalysisRunPublic | null
  selectedRunId: string
}

async function downloadReportArtifact(report: ReportPublic) {
  startReportDownload(await fetchReportDownload(report))
}

export function useReportsRouteState({
  currentPath,
  reportFormatCapabilities,
  capabilitiesError,
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
  const reportGenerationInFlight = useRef(false)
  const [activeReportFormat, setActiveReportFormat] = useState<ReportFormat | "">("")
  const [activeReportWorkflow, setActiveReportWorkflow] =
    useState<WorkflowRunPublic | null>(null)
  const reportsQuery = useQuery({
    enabled: currentPath === "/reports" && Boolean(selectedRunId),
    queryFn: ({ signal }) =>
      ReportsService.readRunReports({ run_id: selectedRunId }, { signal }),
    queryKey: workbenchQueryKeys.reports(selectedRunId),
    refetchInterval: (query) =>
      reportsNeedPolling(query.state.data?.data ?? []) ||
      workflowNeedsPolling(activeReportWorkflow)
        ? 1000
        : false,
    retry: false,
    staleTime: 15_000,
  })
  const createReportMutation = useMutation({
    mutationFn: (format: ReportFormat) =>
      ReportsService.queueRunReport({
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
  const reportActionPending =
    createReportMutation.isPending ||
    Boolean(activeReportFormat) ||
    reportGenerationInFlight.current ||
    workflowNeedsPolling(activeReportWorkflow)
  const reportActionsEnabled = reportActionsAvailable({
    currentPath,
    reportActionPending,
    reportsLoading,
    selectedReportRun,
  }) && !capabilitiesError && reportFormatCapabilities.length > 0

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
    if (!activeReportWorkflow?.id || currentPath !== "/reports") {
      return
    }
    return subscribeWorkflowUpdates({
      workflowId: activeReportWorkflow.id,
      apiBase: OpenAPI.BASE,
      onEvent: () => {
        void queryClient.invalidateQueries({
          queryKey: workbenchQueryKeys.reports(selectedRunId),
        })
      },
      onTerminal: (workflow) => {
        setActiveReportWorkflow(workflow)
        void queryClient.invalidateQueries({
          queryKey: workbenchQueryKeys.reports(selectedRunId),
        })
        if (workflow.status === "failed" || workflow.status === "cancelled") {
          setReportActionError(`Report workflow ${workflowStatusLabel(workflow)}.`)
          return
        }
        setReportActionMessage("Report workflow completed.")
      },
      onWorkflow: setActiveReportWorkflow,
      readWorkflow: (workflowId) =>
        WorkflowsService.readWorkflow({ workflow_id: workflowId }),
      readWorkflowEvents: (workflowId) =>
        WorkflowsService.readWorkflowEvents({
          workflow_id: workflowId,
          limit: 1000,
        }),
    })
  }, [activeReportWorkflow?.id, currentPath, queryClient, selectedRunId])

  useEffect(() => {
    if (!activeReportWorkflow?.id) {
      return
    }
    const completedReport = reports.find(
      (report) => report.workflow?.id === activeReportWorkflow.id,
    )
    if (!completedReport?.workflow || workflowNeedsPolling(completedReport.workflow)) {
      return
    }
    setActiveReportWorkflow(completedReport.workflow)
    setReportActionMessage("Report workflow completed.")
  }, [activeReportWorkflow?.id, reports])

  function refreshReports() {
    void queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.reports(selectedRunId),
    })
  }

  async function createReport(format: ReportFormat) {
    if (reportGenerationInFlight.current) {
      return
    }
    if (
      capabilitiesError ||
      !reportFormatCapabilities.some((capability) => capability.format === format)
    ) {
      setReportActionError(
        capabilitiesError ||
          "Workbench capabilities unavailable. Report generation is disabled until runtime metadata loads.",
      )
      return
    }
    if (!selectedRunId) {
      setReportActionError(
        "Select a completed analysis run before generating reports.",
      )
      return
    }
    setReportActionError("")
    setReportActionMessage("")
    reportGenerationInFlight.current = true
    setActiveReportFormat(format)
    try {
      const workflow = await createReportMutation.mutateAsync(format)
      setActiveReportWorkflow(workflow)
      setReportActionMessage(`${reportFormatLabel(format)} report queued.`)
    } catch (caught) {
      setReportActionError(apiErrorMessage("Report generation failed", caught))
    } finally {
      reportGenerationInFlight.current = false
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
