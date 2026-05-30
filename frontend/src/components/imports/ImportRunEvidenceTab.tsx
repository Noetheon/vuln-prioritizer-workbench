import { Link } from "@/lib/router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ReportPublic } from "@/api-client"
import { ReportsService } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwDataTable,
  VpwPanel,
  VpwSectionHeader,
  VpwSkeletonStack,
  VpwStatusBanner,
} from "@/components/vpw"
import { fetchReportDownload, startReportDownload } from "@/workbench/report-download"
import { workbenchQueryKeys } from "@/workbench/workbench-query-keys"
import {
  formatDateTime,
  formatDisplayType,
  runInputUpload,
  runFileLabel,
} from "./imports-workbench-model"
import { CopyableValue } from "./ImportDiagnosticsDrawerParts"
import { buildImportRunEvidenceColumns } from "./ImportRunEvidenceColumns"
import {
  RunDetailRows,
  stringFromRecord,
  type ImportRun,
  type ImportRunSummary,
} from "./ImportRunDetailTabShared"

export function EvidenceTab({
  run,
  summary,
}: {
  run: ImportRun
  summary: ImportRunSummary
}) {
  const runId = summary.id
  const queryClient = useQueryClient()
  const inputUpload = runInputUpload(summary)
  const reportsQuery = useQuery({
    enabled: Boolean(runId),
    queryFn: ({ signal }) => ReportsService.readRunReports({ run_id: runId }, { signal }),
    queryKey: workbenchQueryKeys.reports(runId),
    retry: false,
    staleTime: 15_000,
  })
  const downloadMutation = useMutation({
    mutationFn: async (report: ReportPublic) => {
      startReportDownload(await fetchReportDownload(report))
    },
  })
  const verifyMutation = useMutation({
    mutationFn: (report: ReportPublic) => ReportsService.verifyReport({ report_id: report.id }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: workbenchQueryKeys.reports(runId) })
    },
  })
  const reports = reportsQuery.data?.data ?? []
  const columns = buildImportRunEvidenceColumns({
    downloadPending: downloadMutation.isPending,
    onDownloadReport: (report) => downloadMutation.mutate(report),
    onVerifyReport: (report) => verifyMutation.mutate(report),
    verifyPending: verifyMutation.isPending,
  })
  if (reportsQuery.isLoading || reportsQuery.isFetching) {
    return (
      <VpwPanel>
        <VpwSkeletonStack rows={4} />
      </VpwPanel>
    )
  }
  if (reportsQuery.isError) {
    return (
      <VpwStatusBanner title="Evidence artifacts unavailable" tone="critical">
        Report history could not be loaded.
      </VpwStatusBanner>
    )
  }
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.75fr)_minmax(0,1.25fr)]">
      <VpwPanel className="flex flex-col gap-4">
        <VpwSectionHeader title="Imported evidence" />
        <RunDetailRows
          items={[
            { label: "Original file", value: runFileLabel(summary) },
            { label: "Input type", value: formatDisplayType(summary.input_type) },
            {
              label: "File hash",
              value: stringFromRecord(inputUpload, "sha256") ? (
                <CopyableValue
                  label="Copy file hash"
                  value={stringFromRecord(inputUpload, "sha256") ?? ""}
                />
              ) : (
                "Not recorded"
              ),
            },
            {
              label: "Storage reference",
              value: stringFromRecord(inputUpload, "storage_ref") ? (
                <CopyableValue
                  label="Copy storage reference"
                  value={stringFromRecord(inputUpload, "storage_ref") ?? ""}
                />
              ) : (
                "Not recorded"
              ),
            },
            { label: "Started", value: formatDateTime(summary.started_at) },
            { label: "Finished", value: formatDateTime(summary.finished_at) },
            { label: "Run ID", value: <CopyableValue label="Copy run ID" value={run.id} /> },
          ]}
        />
        <p className="text-sm leading-6 text-[var(--vpw-text-secondary)]">
          Upload metadata and parser details are available in Diagnostics.
        </p>
      </VpwPanel>
      <VpwPanel className="flex flex-col gap-4">
        <VpwSectionHeader title="Generated report artifacts" />
        {reports.length > 0 ? (
          <VpwDataTable
            caption="Generated report artifacts"
            columns={columns}
            data={reports}
            density="compact"
            getRowKey={(report) => report.id}
            minWidth="640px"
          />
        ) : (
          <div className="rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-4 py-3 text-sm leading-6 text-[var(--vpw-text-secondary)]">
            <p>No report artifacts generated yet.</p>
            <p className="mt-2 font-medium text-[var(--vpw-text-primary)]">
              Available from Evidence Center
            </p>
            <ul className="mt-2 grid gap-1">
              <li>Technical Markdown</li>
              <li>Executive HTML</li>
              <li>Analysis JSON</li>
              <li>Findings CSV</li>
              <li>SARIF</li>
              <li>Evidence ZIP</li>
              <li>ATT&CK Navigator layer, if mapped</li>
            </ul>
          </div>
        )}
        <Button asChild className="w-fit" variant="outline">
          <Link search={{ projectId: summary.project_id, runId }} to="/reports">
            Open Evidence Center
          </Link>
        </Button>
      </VpwPanel>
    </div>
  )
}
