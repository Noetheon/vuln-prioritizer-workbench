import { FileText } from "lucide-react"
import type { ReportPublic, ReportVerificationPublic } from "@/api-client"
import { Skeleton } from "@/components/ui/skeleton"
import {
  VpwDataTable,
  VpwEmptyState,
  VpwTableCard,
} from "@/components/vpw"
import { DEMO_REPORTS } from "@/lib/demo-data"
import { buildReportHistoryColumns } from "./EvidenceCenterHistoryColumns"

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
  const columns = buildReportHistoryColumns({
    isDemo,
    onDownload,
    onVerify,
    verificationLoading,
    verificationReport,
    verificationReportTarget,
  })

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
