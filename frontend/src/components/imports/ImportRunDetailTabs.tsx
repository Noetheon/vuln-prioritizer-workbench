import { Link } from "@/lib/router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Clipboard, Download, RotateCcw } from "lucide-react"
import type { ReportPublic } from "@/api-client"
import { ReportsService } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwKeyValueList,
  VpwPanel,
  VpwSectionHeader,
  VpwSkeletonStack,
  VpwStatusBanner,
} from "@/components/vpw"
import { reportFormatLabel } from "@/lib/report-format"
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
  type ImportsWorkbenchProps,
} from "./imports-workbench-model"

type ImportRun = NonNullable<ImportsWorkbenchProps["selectedRun"]>
type ImportRunSummary = NonNullable<ImportsWorkbenchProps["selectedRunSummary"]>

export function OverviewTab({
  projectName,
  run,
  summary,
}: {
  projectName?: string
  run: ImportRun
  summary: ImportRunSummary
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
            { label: "Project", value: projectName ?? summary.project_id },
            { label: "Input type", value: formatDisplayType(summary.input_type) },
            { label: "Original file", value: runFileLabel(summary) },
            {
              label: "Provider snapshot",
              value: summary.provider_snapshot_id ?? "Not recorded",
            },
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

export function FindingsTab({ summary }: { summary: ImportRunSummary }) {
  const findingsCount =
    summary.finding_count ??
    (summary.created_findings ?? 0) + (summary.updated_findings ?? 0)
  if (findingsCount <= 0) {
    return (
      <VpwPanel className="flex flex-col gap-4">
        <VpwSectionHeader
          description="Parser diagnostics may explain why this import did not create or update findings."
          title="No findings created"
        />
        <div className="flex flex-wrap gap-2">
          <Button asChild>
            <Link search={{ projectId: summary.project_id }} to="/findings">
              Open Triage
            </Link>
          </Button>
        </div>
      </VpwPanel>
    )
  }
  return (
    <VpwPanel className="flex flex-col gap-4">
      <VpwSectionHeader
        description={`This run created ${summary.created_findings ?? 0} and updated ${
          summary.updated_findings ?? 0
        } findings. Open Triage with project context preserved to review and prioritize the results.`}
        title="Findings are ready for triage"
      />
      <VpwKeyValueList
        columns={2}
        density="compact"
        items={[
          { label: "Total findings", value: findingsCount },
          { label: "Created", value: summary.created_findings ?? 0 },
          { label: "Updated", value: summary.updated_findings ?? 0 },
          { label: "Ignored lines", value: summary.ignored_lines ?? 0 },
        ]}
      />
      <div className="flex flex-wrap gap-2">
        <Button asChild>
          <Link search={{ projectId: summary.project_id }} to="/findings">
            Open Triage
          </Link>
        </Button>
      </div>
    </VpwPanel>
  )
}

export function DiagnosticsTab({
  run,
  summary,
}: {
  run: ImportRun
  summary: ImportRunSummary
}) {
  const parseErrors = summary.parse_errors ?? []
  const summaryJson = objectRecord(summary.summary_json)
  const inputUpload = objectRecord(summary.input_upload)
  const warnings = arrayFromRecord(summaryJson, "warnings")
  const rawJson = jsonPreview({ run, summary })
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(360px,0.85fr)]">
      <VpwPanel className="flex flex-col gap-4">
        <VpwSectionHeader title="Parser diagnostics" />
        <VpwKeyValueList
          columns={2}
          density="compact"
          items={[
            { label: "Rows read", value: recordedValue(numberFromSummary(summary, "rows_read")) },
            { label: "Candidate findings", value: candidateFindings(summary) },
            { label: "Findings created", value: summary.created_findings ?? 0 },
            { label: "Findings updated", value: summary.updated_findings ?? 0 },
            { label: "Ignored lines", value: summary.ignored_lines ?? 0 },
            { label: "Parser errors", value: parseErrors.length },
            { label: "Warnings", value: warningCount(summaryJson) },
          ]}
        />
        <div className="flex flex-col gap-3">
          <h3 className="text-sm font-medium text-[var(--vpw-text-primary)]">
            Parser messages
          </h3>
          {parseErrors.length > 0 ? (
            <ParserErrorsTable errors={parseErrors} />
          ) : (
            <p className="rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-3 py-2 text-sm text-[var(--vpw-text-secondary)]">
              No parser errors recorded.
            </p>
          )}
          {warnings.length > 0 ? (
            <ul className="grid gap-2 text-sm text-[var(--vpw-text-secondary)]">
              {warnings.map((warning) => (
                <li
                  className="rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-3 py-2"
                  key={warning}
                >
                  {warning}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      </VpwPanel>
      <div className="grid gap-4">
        <VpwPanel className="flex flex-col gap-4">
          <VpwSectionHeader title="Upload and provider" />
          <VpwKeyValueList
            density="compact"
            items={[
              { label: "Filename", value: runFileLabel(summary) },
              { label: "Input type", value: formatDisplayType(summary.input_type) },
              {
                label: "File hash",
                value: recordedValue(stringFromRecord(inputUpload, "sha256")),
              },
              {
                label: "Storage reference",
                value: recordedValue(stringFromRecord(inputUpload, "storage_ref")),
              },
              {
                label: "Provider data",
                value:
                  stringFromRecord(summaryJson, "provider_snapshot_file") ??
                  stringFromRecord(inputUpload, "provider_snapshot_file") ??
                  "Current provider data",
              },
              {
                label: "Provider snapshot",
                value: summary.provider_snapshot_id ?? "Not recorded",
              },
            ]}
          />
        </VpwPanel>
        <VpwPanel>
          <details>
            <summary className="cursor-pointer text-sm font-medium text-[var(--vpw-text-primary)]">
              Raw diagnostics
            </summary>
            <div className="mt-3 flex justify-end">
              <CopyButton label="Copy diagnostics JSON" value={rawJson} />
            </div>
            <pre className="mt-3 max-h-[20rem] overflow-auto rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-panel)] p-3 text-xs text-[var(--vpw-text-primary)]">
              <code>{rawJson}</code>
            </pre>
          </details>
        </VpwPanel>
      </div>
      {summary.status === "failed" ? (
        <VpwStatusBanner title="Failure cause" tone="critical">
          {failedRunCause(run, summary)}
        </VpwStatusBanner>
      ) : null}
    </div>
  )
}

export function EvidenceTab({
  run,
  summary,
}: {
  run: ImportRun
  summary: ImportRunSummary
}) {
  const runId = summary.id
  const queryClient = useQueryClient()
  const inputUpload = objectRecord(summary.input_upload)
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
    <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.75fr)_minmax(0,1.25fr)]">
      <VpwPanel className="flex flex-col gap-4">
        <VpwSectionHeader title="Imported evidence" />
        <VpwKeyValueList
          density="compact"
          items={[
            { label: "Original file", value: runFileLabel(summary) },
            { label: "Input type", value: formatDisplayType(summary.input_type) },
            {
              label: "File hash",
              value: recordedValue(stringFromRecord(inputUpload, "sha256")),
            },
            {
              label: "Storage reference",
              value: recordedValue(stringFromRecord(inputUpload, "storage_ref")),
            },
            { label: "Started", value: formatDateTime(summary.started_at) },
            { label: "Finished", value: formatDateTime(summary.finished_at) },
            { label: "Run ID", value: run.id },
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
            minWidth="960px"
          />
        ) : (
          <div className="rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-4 py-3 text-sm leading-6 text-[var(--vpw-text-secondary)]">
            No report artifacts generated yet. Generate Technical Markdown, Executive HTML,
            Findings CSV, SARIF, Evidence ZIP, or ATT&CK Navigator from the Evidence Center.
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

export function MetadataTab({
  run,
  summary,
}: {
  run: ImportRun
  summary: ImportRunSummary
}) {
  const inputUpload = objectRecord(summary.input_upload)
  const rawJson = jsonPreview({ run, summary })
  const sha256 = stringFromRecord(inputUpload, "sha256")
  const storageRef = stringFromRecord(inputUpload, "storage_ref")
  return (
    <VpwPanel className="flex flex-col gap-4">
      <VpwSectionHeader title="Run metadata" />
      <VpwKeyValueList
        columns={2}
        density="compact"
        items={[
          { label: "Run ID", value: <CopyableValue label="Copy run ID" value={summary.id} /> },
          { label: "Input type", value: summary.input_type },
          {
            label: "Provider snapshot ID",
            value: summary.provider_snapshot_id ? (
              <CopyableValue
                label="Copy provider snapshot ID"
                value={summary.provider_snapshot_id}
              />
            ) : (
              "Not recorded"
            ),
          },
          {
            label: "SHA256",
            value: sha256 ? <CopyableValue label="Copy SHA256" value={sha256} /> : "Not recorded",
          },
          {
            label: "Storage reference",
            value: storageRef ? (
              <CopyableValue label="Copy storage reference" value={storageRef} />
            ) : (
              "Not recorded"
            ),
          },
        ]}
      />
      <details>
        <summary className="cursor-pointer text-sm font-medium text-[var(--vpw-text-primary)]">
          Raw metadata
        </summary>
        <div className="mt-3 flex justify-end">
          <CopyButton label="Copy metadata JSON" value={rawJson} />
        </div>
        <pre className="mt-3 max-h-[30rem] overflow-auto rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-panel)] p-3 text-xs">
          <code>{rawJson}</code>
        </pre>
      </details>
    </VpwPanel>
  )
}

function CopyableValue({ label, value }: { label: string; value: string }) {
  return (
    <span className="inline-flex max-w-full items-center gap-2">
      <span className="min-w-0 truncate">{value}</span>
      <CopyButton label={label} value={value} />
    </span>
  )
}

function CopyButton({ label, value }: { label: string; value: string }) {
  return (
    <Button
      aria-label={label}
      className="shrink-0"
      onClick={() => void navigator.clipboard?.writeText(value)}
      size="icon-sm"
      type="button"
      variant="ghost"
    >
      <Clipboard aria-hidden="true" />
    </Button>
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

function numberFromSummary(summary: ImportRunSummary, key: string) {
  const value = objectRecord(summary.summary_json)[key]
  return typeof value === "number" ? value : "Not recorded"
}

function recordedValue(value: unknown) {
  if (typeof value === "number") return value
  if (typeof value === "string" && value.trim()) return value
  return "Not recorded"
}

function candidateFindings(summary: ImportRunSummary) {
  const summaryJsonFindingCount = objectRecord(summary.summary_json).finding_count
  if (typeof summary.finding_count === "number") return summary.finding_count
  if (typeof summaryJsonFindingCount === "number") return summaryJsonFindingCount
  return (summary.created_findings ?? 0) + (summary.updated_findings ?? 0)
}

function warningCount(summaryJson: Record<string, unknown>) {
  const warnings = summaryJson.warnings
  if (Array.isArray(warnings)) return warnings.length
  return typeof warnings === "number" ? warnings : "Not recorded"
}

function arrayFromRecord(source: Record<string, unknown>, key: string) {
  const value = source[key]
  if (!Array.isArray(value)) return []
  return value
    .map((item) => (typeof item === "string" ? item.trim() : ""))
    .filter(Boolean)
}
