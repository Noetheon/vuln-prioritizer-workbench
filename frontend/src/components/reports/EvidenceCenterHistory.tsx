import { Download, FileText, History, ShieldCheck } from "lucide-react"
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
  VpwBadge,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwPanel,
} from "@/components/vpw"
import { DEMO_REPORTS } from "@/lib/demo-data"
import {
  formatReportDateTime,
  reportFormatLabel,
  reportSizeLabel,
} from "@/lib/report-format"
import { reportFormatTone, verificationSummary } from "./evidence-center-model"

type HistoryProps = {
  reports: ReportPublic[]
  reportsLoading: boolean
  isDemo: boolean
  verificationReport: ReportVerificationPublic | null
  verificationReportTarget: ReportPublic | null
  verificationLoading: boolean
  onDownload: (report: ReportPublic) => void
  onVerify: (report: ReportPublic) => void
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
            {reportSizeLabel(report.size_bytes)}
          </p>
        </div>
      ),
      className: "min-w-52",
    },
    {
      id: "format",
      header: "Format",
      cell: (report) => (
        <VpwBadge tone={reportFormatTone(report.format)}>
          {reportFormatLabel(report.format)}
        </VpwBadge>
      ),
    },
    {
      id: "generated",
      header: "Generated",
      cell: (report) => (
        <span className="text-sm text-[var(--vpw-text-secondary)]">
          {formatReportDateTime(report.created_at)}
        </span>
      ),
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
        return (
          <VpwBadge
            tone={
              isDemo
                ? "warning"
                : verificationFailed
                  ? "critical"
                  : verificationOk
                    ? "success"
                    : verificationInProgress
                      ? "info"
                      : "success"
            }
          >
            {isDemo
              ? "Demo"
              : verificationInProgress
                ? "Verifying"
                : verificationOk
                  ? "Verified"
                  : verificationFailed
                    ? "Verify failed"
                    : report.format === "zip"
                      ? "Bundle"
                      : "Generated"}
          </VpwBadge>
        )
      },
    },
    {
      id: "actions",
      header: "Actions",
      headerClassName: "text-right",
      className: "text-right",
      cell: (report) => (
        <div className="flex items-center justify-end gap-2">
          {report.format === "zip" && !isDemo ? (
            <Button
              aria-label={`Verify ${report.filename}`}
              aria-busy={
                verificationLoading &&
                verificationReportTarget?.id === report.id
              }
              disabled={
                verificationLoading &&
                verificationReportTarget?.id === report.id
              }
              onClick={() => onVerify(report)}
              size="icon"
              type="button"
              variant="ghost"
            >
              <ShieldCheck aria-hidden="true" className="h-4 w-4" />
            </Button>
          ) : null}
          <Button
            aria-label={`Download ${report.filename}`}
            disabled={isDemo}
            onClick={() => !isDemo && onDownload(report)}
            size="sm"
            type="button"
            variant="outline"
          >
            <Download aria-hidden="true" className="h-4 w-4" />
            Download
          </Button>
        </div>
      ),
    },
  ]

  if (reportsLoading && !isDemo) {
    return (
      <VpwPanel className="min-h-80">
        <div className="mb-4 flex items-center gap-2">
          <History aria-hidden="true" className="h-4 w-4" />
          <h3 className="font-semibold text-[var(--vpw-text-primary)]">
            Report History
          </h3>
        </div>
        <div className="space-y-3">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-3/4" />
        </div>
      </VpwPanel>
    )
  }

  return (
    <VpwPanel className="min-h-80 min-w-0 overflow-hidden p-0">
      <div className="border-b border-[var(--vpw-border-subtle)] p-5">
        <div className="flex items-center justify-between gap-4">
          <div>
            <p className="vpw-label">Generated artifacts</p>
            <h3 className="mt-1 text-lg font-semibold text-[var(--vpw-text-primary)]">
              Report History
            </h3>
          </div>
          <History
            aria-hidden="true"
            className="h-4 w-4 text-[var(--vpw-text-muted)]"
          />
        </div>
      </div>
      <VpwDataTable
        caption="Report history list"
        className="overflow-x-auto"
        columns={columns}
        data={rows}
        density="compact"
        emptyState={
          <VpwEmptyState
            description="Use the artifact cards above to generate the first report for this run."
            icon={<FileText aria-hidden="true" className="h-5 w-5" />}
            title="No reports generated yet"
          />
        }
        getRowKey={(report) => report.id}
      />
    </VpwPanel>
  )
}
