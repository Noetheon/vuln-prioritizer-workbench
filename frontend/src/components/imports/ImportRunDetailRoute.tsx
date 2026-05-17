import { Link } from "@/lib/router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Download, FileSearch, ListChecks, RotateCcw } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwGrid,
  VpwKeyValueList,
  VpwMetricCard,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwSkeletonStack,
  VpwStatusBanner,
} from "@/components/vpw"
import type { ReportPublic } from "@/api-client"
import { ReportsService } from "@/api-client"
import { reportFormatLabel } from "@/lib/report-format"
import { runStatusLabel } from "@/lib/risk-format"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import { fetchReportDownload, startReportDownload } from "@/workbench/report-download"
import { workbenchQueryKeys } from "@/workbench/workbench-query-keys"
import { ParserErrorsTable } from "./ImportsWorkbenchResults"
import {
  failedRunCause,
  formatDateTime,
  formatDisplayType,
  importRunTimelineItems,
  jsonPreview,
  objectRecord,
  runFileLabel,
  runTone,
  type ImportsWorkbenchProps,
} from "./imports-workbench-model"

type ImportRunDetailRouteProps = ImportsWorkbenchProps & {
  onOpenDiagnostics: (runId: string) => void
}

export function ImportRunDetailRoute({
  onOpenDiagnostics,
  runDetailError,
  runDetailLoading,
  selectedRun,
  selectedRunId,
  selectedRunSummary,
}: ImportRunDetailRouteProps) {
  if (runDetailLoading) {
    return (
      <div className="imports-page-shell mx-auto w-full max-w-[1480px]">
        <VpwPanel>
          <VpwSkeletonStack rows={6} />
        </VpwPanel>
      </div>
    )
  }

  if (runDetailError) {
    return (
      <div className="imports-page-shell mx-auto w-full max-w-[1480px]">
        <VpwStatusBanner title="Run detail unavailable" tone="critical">
          {runDetailError}
        </VpwStatusBanner>
      </div>
    )
  }

  if (!selectedRun || !selectedRunSummary) {
    return (
      <div className="imports-page-shell mx-auto w-full max-w-[1480px]">
        <VpwEmptyState
          description="The selected import run could not be loaded."
          title="Import run not found"
        />
      </div>
    )
  }

  const projectSearch = selectedProjectRouteSearch(selectedRunSummary.project_id)
  const reviewFindingsPrimary =
    (selectedRunSummary.finding_count ?? 0) > 0 ||
    (selectedRunSummary.created_findings ?? 0) > 0 ||
    (selectedRunSummary.updated_findings ?? 0) > 0

  return (
    <div className="imports-page-shell mx-auto flex w-full max-w-[1480px] flex-col gap-6">
      <VpwSection>
        <VpwSectionHeader
          actions={
            <>
              <Button
                onClick={() => onOpenDiagnostics(selectedRunId)}
                type="button"
                variant={reviewFindingsPrimary ? "outline" : "default"}
              >
                <FileSearch aria-hidden="true" data-icon="inline-start" />
                Diagnostics
              </Button>
              <Button asChild variant={reviewFindingsPrimary ? "default" : "outline"}>
                <Link search={projectSearch} to="/findings">
                  <ListChecks aria-hidden="true" data-icon="inline-start" />
                  Review findings
                </Link>
              </Button>
            </>
          }
          description={`${formatDisplayType(selectedRunSummary.input_type)} - ${runFileLabel(
            selectedRunSummary,
          )} - ${formatDateTime(selectedRunSummary.started_at)}`}
          title={`Import run ${selectedRunId.slice(0, 8)}`}
        />
        <VpwGrid columns={4}>
          <VpwMetricCard
            label="Status"
            tone={runTone(selectedRunSummary.status)}
            value={runStatusLabel(selectedRunSummary.status)}
          />
          <VpwMetricCard
            label="Created findings"
            value={selectedRunSummary.created_findings ?? 0}
          />
          <VpwMetricCard
            label="Updated findings"
            value={selectedRunSummary.updated_findings ?? 0}
          />
          <VpwMetricCard
            label="Ignored lines"
            tone={(selectedRunSummary.ignored_lines ?? 0) > 0 ? "warning" : "neutral"}
            value={selectedRunSummary.ignored_lines ?? 0}
          />
        </VpwGrid>
      </VpwSection>

      <Tabs defaultValue="overview">
        <TabsList aria-label="Import run detail tabs" className="flex flex-wrap justify-start">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="diagnostics">Diagnostics</TabsTrigger>
          <TabsTrigger value="evidence">Evidence</TabsTrigger>
          <TabsTrigger value="metadata">Metadata</TabsTrigger>
        </TabsList>
        <TabsContent value="overview">
          <OverviewTab run={selectedRun} summary={selectedRunSummary} />
        </TabsContent>
        <TabsContent value="findings">
          <FindingsTab summary={selectedRunSummary} />
        </TabsContent>
        <TabsContent value="diagnostics">
          <DiagnosticsTab run={selectedRun} summary={selectedRunSummary} />
        </TabsContent>
        <TabsContent value="evidence">
          <EvidenceTab runId={selectedRunSummary.id} />
        </TabsContent>
        <TabsContent value="metadata">
          <MetadataTab run={selectedRun} summary={selectedRunSummary} />
        </TabsContent>
      </Tabs>
    </div>
  )
}

function OverviewTab({
  run,
  summary,
}: {
  run: NonNullable<ImportsWorkbenchProps["selectedRun"]>
  summary: NonNullable<ImportsWorkbenchProps["selectedRunSummary"]>
}) {
  const inputUpload = objectRecord(summary.input_upload)
  const summaryJson = objectRecord(summary.summary_json)
  const assetContextUpload = objectRecord(summaryJson.asset_context_upload)
  const vexUpload = objectRecord(summaryJson.vex_upload)
  const lockedProviderData =
    booleanFromRecord(summaryJson, "locked_provider_data") ??
    booleanFromRecord(inputUpload, "locked_provider_data") ??
    "Not recorded"
  const timelineItems = importRunTimelineItems(run, summary)
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <VpwPanel>
        <VpwSectionHeader title="Source details" />
        <VpwKeyValueList
          columns={2}
          items={[
            { label: "Project", value: summary.project_id },
            { label: "Input type", value: formatDisplayType(summary.input_type) },
            { label: "Original file", value: runFileLabel(summary) },
            { label: "Provider snapshot", value: summary.provider_snapshot_id ?? "Not recorded" },
            { label: "Started", value: formatDateTime(summary.started_at) },
            { label: "Finished", value: formatDateTime(summary.finished_at) },
            { label: "Run ID", value: summary.id },
          ]}
        />
      </VpwPanel>
      <VpwPanel>
        <VpwSectionHeader title="Context overlays" />
        <VpwKeyValueList
          items={[
            {
              label: "Asset context",
              value:
                uploadFilename(assetContextUpload) ??
                stringFromRecord(inputUpload, "asset_context_filename") ??
                "None",
            },
            {
              label: "VEX",
              value:
                uploadFilename(vexUpload) ??
                stringFromRecord(inputUpload, "vex_filename") ??
                "None",
            },
            {
              label: "ATT&CK context",
              value:
                stringFromRecord(summaryJson, "attack_source") ??
                stringFromRecord(inputUpload, "attack_source") ??
                "None",
            },
            {
              label: "Provider data",
              value:
                stringFromRecord(summaryJson, "provider_snapshot_file") ??
                stringFromRecord(inputUpload, "provider_snapshot_file") ??
                "Current provider data",
            },
            {
              label: "Deterministic replay",
              value: lockedProviderData,
            },
          ]}
        />
      </VpwPanel>
      <VpwPanel>
        <VpwSectionHeader title="What happened" />
        {timelineItems.length > 0 ? (
          <ol className="grid gap-3 text-sm text-[var(--vpw-text-secondary)]">
            {timelineItems.map((item) => (
              <li className="flex items-center gap-2" key={item}>
                <span className="size-1.5 rounded-full bg-[var(--vpw-text-muted)]" />
                {item}
              </li>
            ))}
          </ol>
        ) : (
          <VpwEmptyState title="No timeline metadata recorded" />
        )}
      </VpwPanel>
      <VpwPanel>
        <VpwSectionHeader title="Next actions" />
        <div className="flex flex-wrap gap-2">
          <Button asChild>
            <Link search={{ projectId: summary.project_id }} to="/findings">
              Review findings
            </Link>
          </Button>
          <Button asChild variant="outline">
            <Link search={{ projectId: summary.project_id, runId: summary.id }} to="/reports">
              Inspect evidence
            </Link>
          </Button>
          <Button asChild variant="outline">
            <Link search={{ projectId: summary.project_id }} to="/imports/new">
              Import another file
            </Link>
          </Button>
        </div>
      </VpwPanel>
      {summary.status === "failed" ? (
        <VpwStatusBanner title="Import failed" tone="critical">
          {failedRunCause(run, summary)}
        </VpwStatusBanner>
      ) : null}
    </div>
  )
}

function FindingsTab({
  summary,
}: {
  summary: NonNullable<ImportsWorkbenchProps["selectedRunSummary"]>
}) {
  const findingsCount =
    summary.finding_count ??
    (summary.created_findings ?? 0) + (summary.updated_findings ?? 0)
  if (findingsCount <= 0) {
    return (
      <VpwEmptyState
        description="Parser diagnostics may explain why no findings were created by this import."
        title="No findings were created by this import"
      />
    )
  }
  return (
    <VpwPanel className="flex flex-col gap-4">
      <VpwStatusBanner title="Findings are available">
        Open Triage for this project. The current API does not expose a dedicated run-scoped findings list.
      </VpwStatusBanner>
      <Button asChild className="w-fit">
        <Link search={{ projectId: summary.project_id }} to="/findings">
          Open Triage filtered by this project
        </Link>
      </Button>
    </VpwPanel>
  )
}

function DiagnosticsTab({
  run,
  summary,
}: {
  run: NonNullable<ImportsWorkbenchProps["selectedRun"]>
  summary: NonNullable<ImportsWorkbenchProps["selectedRunSummary"]>
}) {
  const parseErrors = summary.parse_errors ?? []
  return (
    <VpwPanel className="flex flex-col gap-4">
      <VpwKeyValueList
        columns={2}
        items={[
          { label: "Rows read", value: numberFromSummary(summary, "rows_read") },
          { label: "Findings created", value: summary.created_findings ?? 0 },
          { label: "Findings updated", value: summary.updated_findings ?? 0 },
          { label: "Ignored lines", value: summary.ignored_lines ?? 0 },
          { label: "Parser errors", value: parseErrors.length },
          { label: "Warnings", value: numberFromSummary(summary, "warnings") },
        ]}
      />
      {parseErrors.length > 0 ? (
        <ParserErrorsTable errors={parseErrors} />
      ) : (
        <VpwEmptyState title="No parser errors recorded" />
      )}
      {summary.status === "failed" ? (
        <VpwStatusBanner title="Failure cause" tone="critical">
          {failedRunCause(run, summary)}
        </VpwStatusBanner>
      ) : null}
    </VpwPanel>
  )
}

function EvidenceTab({ runId }: { runId: string }) {
  const queryClient = useQueryClient()
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
  const columns: VpwDataTableColumn<ReportPublic>[] = [
    { id: "artifact", header: "Artifact", cell: (report) => reportFormatLabel(report.format) },
    { id: "format", header: "Format", cell: (report) => report.format },
    { id: "filename", header: "Filename", cell: (report) => report.filename },
    { id: "size", header: "Size", cell: (report) => `${report.size_bytes} B` },
    { id: "created", header: "Created", cell: (report) => formatDateTime(report.created_at) },
    { id: "checksum", header: "Checksum", cell: (report) => report.sha256.slice(0, 12) },
    {
      id: "actions",
      header: "Actions",
      cell: (report) => (
        <div className="vpw-table-actions">
          <Button
            aria-label={`Download ${report.filename}`}
            className="vpw-table-action-button"
            disabled={downloadMutation.isPending}
            onClick={() => downloadMutation.mutate(report)}
            size="icon-sm"
            type="button"
            variant="outline"
          >
            <Download aria-hidden="true" />
          </Button>
          <Button
            aria-label={`Verify ${report.filename}`}
            className="vpw-table-action-button"
            disabled={verifyMutation.isPending}
            onClick={() => verifyMutation.mutate(report)}
            size="icon-sm"
            type="button"
            variant="outline"
          >
            <RotateCcw aria-hidden="true" />
          </Button>
        </div>
      ),
    },
  ]
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
    <VpwPanel className="flex flex-col gap-4">
      {reports.length > 0 ? (
        <VpwDataTable
          caption="Evidence artifacts"
          columns={columns}
          data={reports}
          density="compact"
          getRowKey={(report) => report.id}
          minWidth="960px"
        />
      ) : (
        <VpwEmptyState
          description="Generate evidence in the Evidence Center."
          title="No evidence artifacts generated yet"
        />
      )}
      <Button asChild className="w-fit" variant="outline">
        <Link search={{ runId }} to="/reports">
          Open Evidence Center
        </Link>
      </Button>
    </VpwPanel>
  )
}

function MetadataTab({
  run,
  summary,
}: {
  run: NonNullable<ImportsWorkbenchProps["selectedRun"]>
  summary: NonNullable<ImportsWorkbenchProps["selectedRunSummary"]>
}) {
  return (
    <VpwPanel className="flex flex-col gap-4">
      <VpwKeyValueList
        columns={2}
        items={[
          { label: "Run ID", value: summary.id },
          { label: "Input type", value: summary.input_type },
          { label: "Provider snapshot ID", value: summary.provider_snapshot_id ?? "Not recorded" },
          { label: "SHA256", value: stringFromRecord(summary.input_upload, "sha256") ?? "Not recorded" },
        ]}
      />
      <details>
        <summary className="cursor-pointer text-sm font-medium text-[var(--vpw-text-primary)]">
          Raw metadata
        </summary>
        <pre className="mt-3 max-h-[30rem] overflow-auto rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-panel)] p-3 text-xs">
          <code>{jsonPreview({ run, summary })}</code>
        </pre>
      </details>
    </VpwPanel>
  )
}

function stringFromRecord(source: unknown, key: string) {
  const value = objectRecord(source)[key]
  return typeof value === "string" && value.trim() ? value : null
}

function uploadFilename(source: unknown) {
  return (
    stringFromRecord(source, "original_filename") ??
    stringFromRecord(source, "stored_filename") ??
    stringFromRecord(source, "filename")
  )
}

function booleanFromRecord(source: unknown, key: string) {
  const value = objectRecord(source)[key]
  if (typeof value === "boolean") return value ? "Yes" : "No"
  return null
}

function numberFromSummary(
  summary: NonNullable<ImportsWorkbenchProps["selectedRunSummary"]>,
  key: string,
) {
  const value = objectRecord(summary.summary_json)[key]
  return typeof value === "number" ? value : "Not recorded"
}
