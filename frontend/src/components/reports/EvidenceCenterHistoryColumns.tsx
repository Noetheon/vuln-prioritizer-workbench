import { Download, ShieldCheck } from "lucide-react"
import type { ReportPublic, ReportVerificationPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import type { VpwDataTableColumn } from "@/components/vpw"
import { formatReportDateTime, reportSizeLabel } from "@/lib/report-format"
import { verificationSummary } from "./evidence-center-model"
import {
  ReportArtifactCell,
  ReportChecksumCell,
  ReportStatusCell,
} from "./EvidenceCenterHistoryCells"

type ReportHistoryColumnOptions = {
  isDemo: boolean
  onDownload: (report: ReportPublic) => void
  onVerify: (report: ReportPublic) => void
  verificationLoading: boolean
  verificationReport: ReportVerificationPublic | null
  verificationReportTarget: ReportPublic | null
}

export function buildReportHistoryColumns({
  isDemo,
  onDownload,
  onVerify,
  verificationLoading,
  verificationReport,
  verificationReportTarget,
}: ReportHistoryColumnOptions): VpwDataTableColumn<ReportPublic>[] {
  const verifiedTargetId = verificationReportTarget?.id ?? ""
  const verifiedSummary = verificationSummary(verificationReport)

  return [
    {
      id: "artifact",
      header: "Artifact",
      cell: (report) => <ReportArtifactCell isDemo={isDemo} report={report} />,
      className: "min-w-52",
      width: "28%",
    },
    {
      id: "status",
      header: "Status",
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
          verificationOk={verifiedTargetId === report.id && verifiedSummary.ok === true}
        />
      ),
      width: "12%",
    },
    {
      id: "size",
      header: "Size",
      cell: (report) => reportSizeLabel(report.size_bytes),
      width: "10%",
    },
    {
      id: "checksum",
      header: "Checksum",
      cell: (report) => <ReportChecksumCell report={report} />,
      width: "18%",
    },
    {
      id: "generated",
      header: "Generated",
      cell: (report) => (
        <span className="text-sm text-[var(--vpw-text-secondary)]">
          {formatReportDateTime(report.created_at)}
        </span>
      ),
      width: "18%",
    },
    {
      id: "actions",
      header: "Actions",
      headerClassName: "text-right",
      className: "min-w-[5rem] text-right",
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
      width: "5rem",
    },
  ]
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
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              aria-label={`Verify ${report.filename}`}
              aria-busy={verificationDisabled}
              className="vpw-table-action-button"
              disabled={verificationDisabled}
              onClick={() => onVerify(report)}
              size="icon-sm"
              type="button"
              variant="outline"
            >
              <ShieldCheck aria-hidden="true" className="h-4 w-4" />
            </Button>
          </TooltipTrigger>
          <TooltipContent side="left">Verify bundle</TooltipContent>
        </Tooltip>
      ) : null}
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            aria-label={`Download ${report.filename}`}
            className="vpw-table-action-button"
            disabled={isDemo}
            onClick={() => !isDemo && onDownload(report)}
            size="icon-sm"
            type="button"
            variant="outline"
          >
            <Download aria-hidden="true" className="h-4 w-4" />
          </Button>
        </TooltipTrigger>
        <TooltipContent side="left">Download report</TooltipContent>
      </Tooltip>
    </div>
  )
}
