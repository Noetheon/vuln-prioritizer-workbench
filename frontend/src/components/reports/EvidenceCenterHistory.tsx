import { FileText } from "lucide-react"
import type { ReportPublic, ReportVerificationPublic } from "@/api-client"
import { Skeleton } from "@/components/ui/skeleton"
import { VpwDataTable, VpwEmptyState, VpwTableCard } from "@/components/vpw"
import { buildReportHistoryColumns } from "./EvidenceCenterHistoryColumns"

type HistoryProps = {
  reports: ReportPublic[]
  reportsLoading: boolean
  verificationReport: ReportVerificationPublic | null
  verificationReportTarget: ReportPublic | null
  verificationLoading: boolean
  onDownload: (report: ReportPublic) => void
  onVerify: (report: ReportPublic) => void
  mode?: "inventory" | "history"
  emptyDescription?: string
  panelDescription?: string
  panelEyebrow?: string
  panelTitle?: string
}

export function ReportHistory({
  onDownload,
  onVerify,
  mode = "history",
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
  const rows = reports
  const columns = buildReportHistoryColumns({
    mode,
    onDownload,
    onVerify,
    verificationLoading,
    verificationReport,
    verificationReportTarget,
  })

  if (reportsLoading) {
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
        minWidth={mode === "inventory" ? "1040px" : "960px"}
      />
    </VpwTableCard>
  )
}
