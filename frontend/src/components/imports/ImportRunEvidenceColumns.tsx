import { Download, RotateCcw } from "lucide-react"
import type { ReportPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import type { VpwDataTableColumn } from "@/components/vpw"
import { reportFormatLabel } from "@/lib/report-format"

type BuildImportRunEvidenceColumnsArgs = {
  downloadPending: boolean
  onDownloadReport: (report: ReportPublic) => void
  onVerifyReport: (report: ReportPublic) => void
  verifyPending: boolean
}

export function buildImportRunEvidenceColumns({
  downloadPending,
  onDownloadReport,
  onVerifyReport,
  verifyPending,
}: BuildImportRunEvidenceColumnsArgs): readonly VpwDataTableColumn<ReportPublic>[] {
  return [
    {
      id: "artifact",
      header: "Artifact",
      cell: (report) => (
        <div className="min-w-0">
          <span className="block font-medium text-[var(--vpw-text-primary)]">
            {reportFormatLabel(report.format)}
          </span>
          <span className="vpw-table-subtext">{report.format}</span>
        </div>
      ),
    },
    {
      id: "filename",
      header: "Filename",
      cell: (report) => (
        <span className="block max-w-[16rem] [overflow-wrap:anywhere]">
          {report.filename}
        </span>
      ),
    },
    { id: "size", header: "Size", cell: (report) => `${report.size_bytes} B` },
    {
      id: "actions",
      header: "Actions",
      className: "text-right",
      headerClassName: "text-right",
      cell: (report) => (
        <div className="vpw-table-actions">
          {isVerifiableEvidenceBundle(report) ? (
            <Button
              aria-label={`Verify ${report.filename}`}
              className="vpw-table-action-button"
              disabled={verifyPending}
              onClick={() => onVerifyReport(report)}
              size="icon-sm"
              type="button"
              variant="outline"
            >
              <RotateCcw aria-hidden="true" />
            </Button>
          ) : null}
          <Button
            aria-label={`Download ${report.filename}`}
            className="vpw-table-action-button"
            disabled={downloadPending}
            onClick={() => onDownloadReport(report)}
            size="icon-sm"
            type="button"
            variant="outline"
          >
            <Download aria-hidden="true" />
          </Button>
        </div>
      ),
    },
  ]
}

function isVerifiableEvidenceBundle(report: ReportPublic) {
  return report.format === "zip" && report.kind === "evidence-bundle"
}
