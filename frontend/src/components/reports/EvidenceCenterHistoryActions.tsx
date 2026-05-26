import { Clipboard, Download, ShieldCheck } from "lucide-react"
import type { ReportPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"

export function ReportHistoryActionsCell({
  onDownload,
  onVerify,
  report,
  verificationLoading,
  verificationReportTarget,
}: {
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
      {report.format === "zip" ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              aria-busy={verificationDisabled}
              aria-label={`Verify ${report.filename}`}
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
            onClick={() => onDownload(report)}
            size="icon-sm"
            type="button"
            variant="outline"
          >
            <Download aria-hidden="true" className="h-4 w-4" />
          </Button>
        </TooltipTrigger>
        <TooltipContent side="left">Download artifact</TooltipContent>
      </Tooltip>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            aria-label={`Copy checksum for ${report.filename}`}
            className="vpw-table-action-button"
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
