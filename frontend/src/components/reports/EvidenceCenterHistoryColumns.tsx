import type { ReportPublic, ReportVerificationPublic } from "@/api-client"
import type { VpwDataTableColumn } from "@/components/vpw"
import { formatReportDateTime, reportSizeLabel } from "@/lib/report-format"
import {
  artifactFormatLabel,
  artifactVerificationLabel,
  reportHistoryAction,
  reportRunLabel,
  verificationSummary,
} from "./evidence-center-model"
import { ReportHistoryActionsCell } from "./EvidenceCenterHistoryActions"
import {
  ReportArtifactCell,
  ReportChecksumCell,
  ReportStatusCell,
  ReportVerificationCell,
} from "./EvidenceCenterHistoryCells"

type ReportHistoryColumnOptions = {
  mode: "inventory" | "history"
  onDownload: (report: ReportPublic) => void
  onVerify: (report: ReportPublic) => void
  verificationLoading: boolean
  verificationReport: ReportVerificationPublic | null
  verificationReportTarget: ReportPublic | null
}

type ReportVerificationFlags = {
  verificationFailed: boolean
  verificationInProgress: boolean
  verificationOk: boolean
}

export function buildReportHistoryColumns({
  mode,
  onDownload,
  onVerify,
  verificationLoading,
  verificationReport,
  verificationReportTarget,
}: ReportHistoryColumnOptions): VpwDataTableColumn<ReportPublic>[] {
  const verifiedSummary = verificationSummary(verificationReport)
  const verificationFlags = (report: ReportPublic) =>
    reportVerificationFlags({
      report,
      verificationLoading,
      verificationReport: Boolean(verificationReport),
      verificationReportTarget,
      verificationSummaryOk: verifiedSummary.ok === true,
    })

  if (mode === "history") {
    return [
      {
        cell: (report) => (
          <span className="text-sm text-[var(--vpw-text-secondary)]">
            {formatReportDateTime(report.created_at)}
          </span>
        ),
        header: "Time",
        id: "time",
        width: "17%",
      },
      {
        cell: (report) => reportHistoryAction(report),
        header: "Action",
        id: "action",
        width: "12%",
      },
      {
        cell: (report) => <ReportArtifactCell report={report} />,
        className: "min-w-52",
        header: "Artifact",
        id: "artifact",
        width: "22%",
      },
      {
        cell: (report) => (
          <span className="vpw-table-cell-nowrap">
            {artifactFormatLabel(report)}
          </span>
        ),
        header: "Format",
        id: "format",
        width: "10%",
      },
      {
        cell: (report) => (
          <ReportStatusCell report={report} {...verificationFlags(report)} />
        ),
        header: "Status",
        id: "status",
        width: "11%",
      },
      {
        cell: (report) => <ReportChecksumCell report={report} />,
        header: "Checksum",
        id: "checksum",
        width: "15%",
      },
      {
        cell: (report) => (
          <span
            className="font-mono text-xs text-[var(--vpw-text-secondary)]"
            data-vpw-visual-mask="true"
          >
            {reportRunLabel(report)}
          </span>
        ),
        header: "Run",
        id: "run",
        width: "8%",
      },
      actionColumn({
        onDownload,
        onVerify,
        verificationLoading,
        verificationReportTarget,
      }),
    ]
  }

  return [
    {
      cell: (report) => <ReportArtifactCell report={report} />,
      className: "min-w-52",
      header: "Artifact",
      id: "artifact",
      width: "23%",
    },
    {
      cell: (report) => (
        <span className="vpw-table-cell-nowrap">
          {artifactFormatLabel(report)}
        </span>
      ),
      header: "Format",
      id: "format",
      width: "10%",
    },
    {
      cell: (report) => (
        <ReportStatusCell report={report} {...verificationFlags(report)} />
      ),
      header: "Status",
      id: "status",
      width: "11%",
    },
    {
      cell: (report) => (
        <span data-vpw-visual-mask="true">
          {reportSizeLabel(report.size_bytes)}
        </span>
      ),
      header: "Size",
      id: "size",
      width: "9%",
    },
    {
      cell: (report) => (
        <ReportVerificationCell
          label={artifactVerificationLabel({
            report,
            verificationLoading,
            verificationReport,
            verificationReportTarget,
          })}
        />
      ),
      header: "Verification",
      id: "verification",
      width: "14%",
    },
    {
      cell: (report) => <ReportChecksumCell report={report} />,
      header: "Checksum",
      id: "checksum",
      width: "15%",
    },
    {
      cell: (report) => (
        <span className="text-sm text-[var(--vpw-text-secondary)]">
          {formatReportDateTime(report.created_at)}
        </span>
      ),
      header: "Generated",
      id: "generated",
      width: "14%",
    },
    actionColumn({
      onDownload,
      onVerify,
      verificationLoading,
      verificationReportTarget,
    }),
  ]
}

function reportVerificationFlags({
  report,
  verificationLoading,
  verificationReport,
  verificationReportTarget,
  verificationSummaryOk,
}: {
  report: ReportPublic
  verificationLoading: boolean
  verificationReport: boolean
  verificationReportTarget: ReportPublic | null
  verificationSummaryOk: boolean
}): ReportVerificationFlags {
  const isVerificationTarget = verificationReportTarget?.id === report.id

  return {
    verificationFailed:
      isVerificationTarget && verificationReport && !verificationSummaryOk,
    verificationInProgress: isVerificationTarget && verificationLoading,
    verificationOk: isVerificationTarget && verificationSummaryOk,
  }
}

function actionColumn({
  onDownload,
  onVerify,
  verificationLoading,
  verificationReportTarget,
}: {
  onDownload: (report: ReportPublic) => void
  onVerify: (report: ReportPublic) => void
  verificationLoading: boolean
  verificationReportTarget: ReportPublic | null
}): VpwDataTableColumn<ReportPublic> {
  return {
    cell: (report) => (
      <ReportHistoryActionsCell
        onDownload={onDownload}
        onVerify={onVerify}
        report={report}
        verificationLoading={verificationLoading}
        verificationReportTarget={verificationReportTarget}
      />
    ),
    className: "min-w-28 text-right",
    header: "Actions",
    headerClassName: "text-right",
    id: "actions",
    width: "7rem",
  }
}
