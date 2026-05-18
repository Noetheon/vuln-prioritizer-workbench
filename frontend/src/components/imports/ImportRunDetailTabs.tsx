import { Link } from "@/lib/router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  CheckCircle2,
  ChevronRight,
  Clipboard,
  Download,
  FolderOpen,
  ListChecks,
  RotateCcw,
  UploadCloud,
} from "lucide-react"
import type { ReactNode } from "react"
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
import { runStatusLabel } from "@/lib/risk-format"
import { cn } from "@/lib/utils"
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
        <RunDetailRows
          items={[
            { label: "Project", value: projectName ?? summary.project_id },
            { label: "Input type", value: formatDisplayType(summary.input_type) },
            { label: "Original file", value: runFileLabel(summary) },
            {
              label: "Provider snapshot",
              value: summary.provider_snapshot_id ? (
                <CopyableValue
                  label="Copy provider snapshot ID"
                  value={summary.provider_snapshot_id}
                />
              ) : (
                "Not recorded"
              ),
            },
            { label: "Started", value: formatDateTime(summary.started_at) },
            { label: "Finished", value: formatDateTime(summary.finished_at) },
            { label: "Run ID", value: <CopyableValue label="Copy run ID" value={summary.id} /> },
          ]}
        />
      </VpwPanel>
      <VpwPanel>
        <VpwSectionHeader title="Context overlays" />
        <RunDetailRows
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
          <ol className="grid gap-3 text-sm">
            {timelineItems.map((item) => (
              <li className="grid grid-cols-[1.5rem_minmax(0,1fr)_auto] items-start gap-3" key={item}>
                <CheckCircle2
                  aria-hidden="true"
                  className="mt-0.5 size-4 text-[var(--vpw-green)]"
                />
                <span className="min-w-0">
                  <span className="block font-semibold text-[var(--vpw-text-primary)]">
                    {item}
                  </span>
                  <span className="block text-sm text-[var(--vpw-text-secondary)]">
                    {timelineDetail(item, summary)}
                  </span>
                </span>
                <span className="text-sm text-[var(--vpw-text-secondary)]">
                  {timelineTime(item, summary)}
                </span>
              </li>
            ))}
          </ol>
        ) : (
          <VpwEmptyState title="No timeline metadata recorded" />
        )}
      </VpwPanel>
      <VpwPanel>
        <VpwSectionHeader title="Next actions" />
        <div className="grid gap-3">
          {[
            {
              description: "Open Triage with this project context preserved.",
              href: "/findings" as const,
              icon: ListChecks,
              label: "Review findings",
              search: { projectId: summary.project_id },
            },
            {
              description: "Review imported file metadata and report artifacts.",
              href: "/reports" as const,
              icon: FolderOpen,
              label: "Inspect evidence",
              search: { projectId: summary.project_id, runId: summary.id },
            },
            {
              description: "Start another guided import.",
              href: "/imports/new" as const,
              icon: UploadCloud,
              label: "Import another file",
              search: { projectId: summary.project_id },
            },
          ].map(({ description, href, icon: Icon, label, search }) => (
            <Link
              className="group flex items-center gap-3 rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-3 py-3 text-sm transition-colors hover:border-[var(--vpw-border-strong)] hover:bg-[var(--vpw-bg-panel)]"
              key={label}
              search={search}
              to={href}
            >
              <Icon aria-hidden="true" className="size-4 shrink-0 text-[var(--vpw-text-primary)]" />
              <span className="min-w-0 flex-1">
                <span className="block font-semibold text-[var(--vpw-text-primary)]">
                  {label}
                </span>
                <span className="block text-sm text-[var(--vpw-text-secondary)]">
                  {description}
                </span>
              </span>
              <ChevronRight
                aria-hidden="true"
                className="size-4 shrink-0 text-[var(--vpw-text-muted)] transition-transform group-hover:translate-x-0.5"
              />
            </Link>
          ))}
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
        <RunDetailRows
          items={[
            { label: "Status", value: runStatusLabel(summary.status) },
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
          <RunDetailRows
            items={[
              { label: "Filename", value: runFileLabel(summary) },
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
              {
                label: "Provider data",
                value:
                  stringFromRecord(summaryJson, "provider_snapshot_file") ??
                  stringFromRecord(inputUpload, "provider_snapshot_file") ??
                  "Current provider data",
              },
              {
                label: "Provider snapshot",
                value: summary.provider_snapshot_id ? (
                  <CopyableValue
                    label="Copy provider snapshot ID"
                    value={summary.provider_snapshot_id}
                  />
                ) : (
                  "Not recorded"
                ),
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
              disabled={verifyMutation.isPending}
              onClick={() => verifyMutation.mutate(report)}
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
            disabled={downloadMutation.isPending}
            onClick={() => downloadMutation.mutate(report)}
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
      <RunDetailRows
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

function isVerifiableEvidenceBundle(report: ReportPublic) {
  return report.format === "zip" && report.kind === "evidence-bundle"
}

function RunDetailRows({
  className,
  items,
}: {
  className?: string
  items: readonly { label: string; value: ReactNode }[]
}) {
  return (
    <dl
      className={cn(
        "divide-y divide-[var(--vpw-border-subtle)] overflow-hidden rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] text-sm",
        className,
      )}
    >
      {items.map((item) => (
        <div
          className="grid gap-1 px-3 py-2.5 sm:grid-cols-[9.5rem_minmax(0,1fr)] sm:gap-4"
          key={item.label}
        >
          <dt className="vpw-label">{item.label}</dt>
          <dd className="min-w-0 font-medium text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]">
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  )
}

function CopyableValue({ label, value }: { label: string; value: string }) {
  return (
    <span className="inline-flex max-w-full items-center gap-2">
      <span className="min-w-0 truncate" title={value}>
        {value}
      </span>
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

function timelineDetail(item: string, summary: ImportRunSummary) {
  const created = summary.created_findings ?? 0
  const updated = summary.updated_findings ?? 0
  if (item === "File uploaded") return runFileLabel(summary)
  if (item === "Data parsed") return `${candidateFindings(summary)} candidate findings`
  if (item === "Provider data applied") {
    return summary.provider_snapshot_id
      ? `${summary.provider_snapshot_id} snapshot`
      : "Current provider data"
  }
  if (item === "Optional context applied") return "Reviewed supplemental context"
  if (item === "Findings created or updated") {
    return `${created} created, ${updated} updated`
  }
  if (item === "Import completed") return runStatusLabel(summary.status)
  if (item === "Parser diagnostics recorded") {
    return `${summary.parse_errors?.length ?? 0} parser error(s)`
  }
  return formatDisplayType(summary.input_type)
}

function timelineTime(item: string, summary: ImportRunSummary) {
  if (item === "Import completed") return formatDateTime(summary.finished_at)
  return item === "Findings created or updated"
    ? `${summary.created_findings ?? 0} created`
    : formatDateTime(summary.started_at)
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
