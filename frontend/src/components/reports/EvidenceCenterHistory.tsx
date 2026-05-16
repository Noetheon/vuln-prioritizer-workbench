import { Download, FileText, ShieldCheck } from "lucide-react"
import type { ReportPublic, ReportVerificationPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  StatusLozenge,
  VpwBadge,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwTableCard,
} from "@/components/vpw"
import { DEMO_REPORTS } from "@/lib/demo-data"
import {
  formatReportDateTime,
  reportFormatLabel,
  reportSizeLabel,
} from "@/lib/report-format"
import { verificationSummary } from "./evidence-center-model"

type HistoryProps = {
  reports: ReportPublic[]
  reportsLoading: boolean
  isDemo: boolean
  verificationReport: ReportVerificationPublic | null
  verificationReportTarget: ReportPublic | null
  verificationLoading: boolean
  onDownload: (report: ReportPublic) => void
  onVerify: (report: ReportPublic) => void
  emptyDescription?: string
  panelDescription?: string
  panelEyebrow?: string
  panelTitle?: string
}

export function ReportHistory({
  isDemo,
  onDownload,
  onVerify,
  reports,
  reportsLoading,
  verificationLoading,
  verificationReport,
  verificationReportTarget,
  emptyDescription = "Use the artifact cards above to generate the first report for this run.",
  panelDescription = "Previously generated reports for the selected run.",
  panelEyebrow = "Generated artifacts",
  panelTitle = "Report History",
}: HistoryProps) {
  const rows = isDemo ? DEMO_REPORTS : reports
  const verifiedTargetId = verificationReportTarget?.id ?? ""
  const verifiedSummary = verificationSummary(verificationReport)
  const columns: VpwDataTableColumn<ReportPublic>[] = [
    {
      id: "artifact",
      header: "Artifact",
      cell: (report) => (
        <div className="min-w-0">
          <div className="flex min-w-0 items-center gap-2">
            <span className="truncate font-mono text-xs font-medium">
              {report.filename}
            </span>
            {isDemo ? <VpwBadge tone="warning">Demo</VpwBadge> : null}
          </div>
          <p className="mt-1 text-xs text-[var(--vpw-text-secondary)]">
            {reportFormatLabel(report.format)}
          </p>
        </div>
      ),
      className: "min-w-52",
      width: "28%",
    },
    {
      id: "status",
      header: "Status",
      cell: (report) => {
        const isVerificationTarget = verifiedTargetId === report.id
        const verificationOk =
          isVerificationTarget && verifiedSummary.ok === true
        const verificationFailed = Boolean(
          isVerificationTarget &&
            verificationReport &&
            verifiedSummary.ok !== true,
        )
        const verificationInProgress =
          isVerificationTarget && verificationLoading
        const status = isDemo
          ? "ready"
          : verificationInProgress
            ? "in_review"
            : verificationOk
              ? "succeeded"
              : verificationFailed
                ? "failed"
                : "succeeded"
        const label = isDemo
          ? "Demo"
          : verificationInProgress
            ? "Verifying"
            : verificationOk
              ? "Verified"
              : verificationFailed
                ? "Verify failed"
                : report.format === "zip"
                  ? "Bundle"
                  : "Generated"
        return (
          <StatusLozenge density="compact" label={label} status={status} />
        )
      },
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
      cell: (report) => {
        const realChecksum = !report.sha256.startsWith("demo-only")
        const checksum = realChecksum
          ? `${report.sha256.slice(0, 12)}...`
          : "Demo preview"
        return (
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="cursor-default font-mono text-xs text-[var(--vpw-text-secondary)]">
                  {checksum}
                </span>
              </TooltipTrigger>
              <TooltipContent>
                {realChecksum
                  ? report.sha256
                  : "Demo preview - not a real checksum"}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        )
      },
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
        <div className="vpw-table-actions">
          {report.format === "zip" && !isDemo ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  aria-label={`Verify ${report.filename}`}
                  aria-busy={
                    verificationLoading &&
                    verificationReportTarget?.id === report.id
                  }
                  className="vpw-table-action-button"
                  disabled={
                    verificationLoading &&
                    verificationReportTarget?.id === report.id
                  }
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
      ),
      width: "5rem",
    },
  ]

  if (reportsLoading && !isDemo) {
    return (
      <VpwTableCard
        className="min-h-80"
        description={panelDescription}
        eyebrow={panelEyebrow}
        title={panelTitle}
      >
        <div className="flex flex-col gap-3">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-3/4" />
        </div>
      </VpwTableCard>
    )
  }

  return (
    <VpwTableCard
      className="min-h-80"
      description={panelDescription}
      eyebrow={panelEyebrow}
      title={panelTitle}
    >
      <VpwDataTable
        caption="Report history list"
        columns={columns}
        data={rows}
        density="compact"
        emptyState={
          <VpwEmptyState
            description={emptyDescription}
            icon={<FileText aria-hidden="true" className="h-5 w-5" />}
            title="No reports generated yet"
          />
        }
        getRowKey={(report) => report.id}
        minWidth="860px"
      />
    </VpwTableCard>
  )
}
