import { Clipboard, Download, ShieldCheck } from "lucide-react"
import type { ReportPublic, ReportVerificationPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import type { VpwDataTableColumn } from "@/components/vpw"
import { formatReportDateTime, reportSizeLabel } from "@/lib/report-format"
import {
  artifactFormatLabel,
  artifactVerificationLabel,
  reportHistoryAction,
  reportRunLabel,
  verificationSummary,
} from "./evidence-center-model"
import {
  ReportArtifactCell,
  ReportChecksumCell,
  ReportStatusCell,
  ReportVerificationCell,
} from "./EvidenceCenterHistoryCells"

type ReportHistoryColumnOptions = {
  isDemo: boolean
  mode: "inventory" | "history"
  onDownload: (report: ReportPublic) => void
  onVerify: (report: ReportPublic) => void
  verificationLoading: boolean
  verificationReport: ReportVerificationPublic | null
  verificationReportTarget: ReportPublic | null
}

export function buildReportHistoryColumns({
  isDemo,
  mode,
  onDownload,
  onVerify,
  verificationLoading,
  verificationReport,
  verificationReportTarget,
}: ReportHistoryColumnOptions): VpwDataTableColumn<ReportPublic>[] {
  const verifiedTargetId = verificationReportTarget?.id ?? ""
  const verifiedSummary = verificationSummary(verificationReport)

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
        cell: (report) => (
          <ReportArtifactCell isDemo={isDemo} report={report} />
        ),
        className: "min-w-52",
        header: "Artifact",
        id: "artifact",
        width: "22%",
      },
      {
        cell: (report) => artifactFormatLabel(report),
        header: "Format",
        id: "format",
        width: "10%",
      },
      {
        cell: (report) => (
          <ReportStatusCell
            isDemo={isDemo}
            report={report}
            verificationFailed={Boolean(
              verifiedTargetId === report.id &&
                verificationReport &&
                verifiedSummary.ok !== true,
            )}
            verificationInProgress={
              verifiedTargetId === report.id && verificationLoading
            }
            verificationOk={
              verifiedTargetId === report.id && verifiedSummary.ok === true
            }
          />
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
          <span className="font-mono text-xs text-[var(--vpw-text-secondary)]">
            {reportRunLabel(report)}
          </span>
        ),
        header: "Run",
        id: "run",
        width: "8%",
      },
      actionColumn({
        isDemo,
        onDownload,
        onVerify,
        verificationLoading,
        verificationReportTarget,
      }),
    ]
  }

  return [
    {
      cell: (report) => <ReportArtifactCell isDemo={isDemo} report={report} />,
      className: "min-w-52",
      header: "Artifact",
      id: "artifact",
      width: "23%",
    },
    {
      cell: (report) => artifactFormatLabel(report),
      header: "Format",
      id: "format",
      width: "10%",
    },
    {
      cell: (report) => (
        <ReportStatusCell
          isDemo={isDemo}
          report={report}
          verificationFailed={Boolean(
            verifiedTargetId === report.id &&
              verificationReport &&
              verifiedSummary.ok !== true,
          )}
          verificationInProgress={
            verifiedTargetId === report.id && verificationLoading
          }
          verificationOk={
            verifiedTargetId === report.id && verifiedSummary.ok === true
          }
        />
      ),
      header: "Status",
      id: "status",
      width: "11%",
    },
    {
      cell: (report) => reportSizeLabel(report.size_bytes),
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
      isDemo,
      onDownload,
      onVerify,
      verificationLoading,
      verificationReportTarget,
    }),
  ]
}

function actionColumn({
  isDemo,
  onDownload,
  onVerify,
  verificationLoading,
  verificationReportTarget,
}: {
  isDemo: boolean
  onDownload: (report: ReportPublic) => void
  onVerify: (report: ReportPublic) => void
  verificationLoading: boolean
  verificationReportTarget: ReportPublic | null
}): VpwDataTableColumn<ReportPublic> {
  return {
    cell: (report) => (
      <ReportHistoryActionsCell
        isDemo={isDemo}
        onDownload={onDownload}
        onVerify={onVerify}
        report={report}
        verificationLoading={verificationLoading}
        verificationReportTarget={verificationReportTarget}
      />
    ),
    className: "min-w-[15rem] text-right",
    header: "Actions",
    headerClassName: "text-right",
    id: "actions",
    width: "15rem",
  }
}

function ReportHistoryActionsCell({
  isDemo,
  onDownload,
  onVerify,
  report,
  verificationLoading,
  verificationReportTarget,
}: {
  isDemo: boolean
  onDownload: (report: ReportPublic) => void
  onVerify: (report: ReportPublic) => void
  report: ReportPublic
  verificationLoading: boolean
  verificationReportTarget: ReportPublic | null
}) {
  const isVerificationTarget = verificationReportTarget?.id === report.id
  const verificationDisabled = verificationLoading && isVerificationTarget

  return (
    <div className="vpw-table-actions">
      {report.format === "zip" && !isDemo ? (
        <Button
          aria-label={`Verify ${report.filename}`}
          aria-busy={verificationDisabled}
          disabled={verificationDisabled}
          onClick={() => onVerify(report)}
          size="xs"
          type="button"
          variant="outline"
        >
          <ShieldCheck aria-hidden="true" data-icon="inline-start" />
          Verify
        </Button>
      ) : null}
      <Button
        aria-label={`Download ${report.filename}`}
        disabled={isDemo}
        onClick={() => !isDemo && onDownload(report)}
        size="xs"
        type="button"
        variant="outline"
      >
        <Download aria-hidden="true" data-icon="inline-start" />
        Download
      </Button>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            aria-label={`Copy checksum for ${report.filename}`}
            className="vpw-table-action-button"
            disabled={isDemo}
            onClick={() => void navigator.clipboard.writeText(report.sha256)}
            size="icon-sm"
            type="button"
            variant="outline"
          >
            <Clipboard aria-hidden="true" className="h-4 w-4" />
          </Button>
        </TooltipTrigger>
        <TooltipContent side="left">Copy checksum</TooltipContent>
      </Tooltip>
    </div>
  )
}
