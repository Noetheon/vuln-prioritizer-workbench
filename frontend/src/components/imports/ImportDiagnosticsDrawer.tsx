import { Link } from "@/lib/router"
import type { AnalysisRunPublic, AnalysisRunSummaryPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  VpwEmptyState,
  VpwPanel,
  VpwSkeletonStack,
  VpwStatusBanner,
} from "@/components/vpw"
import { runStatusLabel } from "@/lib/risk-format"
import {
  CompactRows,
  CopyableValue,
  CopyButton,
  recordedValue,
  stringValue,
  warningCount,
} from "./ImportDiagnosticsDrawerParts"
import { ParserErrorsTable } from "./ImportsWorkbenchResults"
import {
  failedRunCause,
  formatDateTime,
  formatDisplayType,
  jsonPreview,
  metadataRows,
  objectRecord,
  runFileLabel,
} from "./imports-workbench-model"

type ImportDiagnosticsDrawerProps = {
  diagnosticsOpen: boolean
  diagnosticsRunId: string
  onDiagnosticsOpenChange: (open: boolean) => void
  runDetailError: string
  runDetailLoading: boolean
  selectedRun: AnalysisRunPublic | null
  selectedRunId: string
  selectedRunSummary: AnalysisRunSummaryPublic | null
}

export function ImportDiagnosticsDrawer({
  diagnosticsOpen,
  diagnosticsRunId,
  onDiagnosticsOpenChange,
  runDetailError,
  runDetailLoading,
  selectedRun,
  selectedRunId,
  selectedRunSummary,
}: ImportDiagnosticsDrawerProps) {
  const waitingForSelectedRun = Boolean(
    diagnosticsRunId && selectedRunId !== diagnosticsRunId,
  )

  return (
    <Sheet open={diagnosticsOpen} onOpenChange={onDiagnosticsOpenChange}>
      <SheetContent className="vpw-sheet-content h-[100dvh] w-screen max-w-none gap-0 overflow-hidden p-0 max-sm:left-0 max-sm:right-0 max-sm:w-auto max-sm:max-w-none sm:w-[600px] sm:max-w-[640px]">
        <SheetHeader className="shrink-0 border-b border-[var(--vpw-border-subtle)] px-5 py-4 pr-12 text-left">
          <SheetTitle>Run diagnostics</SheetTitle>
          <SheetDescription>
            Run ID {diagnosticsRunId ? diagnosticsRunId.slice(0, 8) : "not selected"}
          </SheetDescription>
        </SheetHeader>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          {waitingForSelectedRun || runDetailLoading ? (
            <VpwPanel>
              <VpwSkeletonStack rows={5} />
            </VpwPanel>
          ) : runDetailError ? (
            <VpwStatusBanner title="Run detail unavailable" tone="critical">
              {runDetailError}
            </VpwStatusBanner>
          ) : selectedRun && selectedRunSummary ? (
            <DiagnosticsTabs
              run={selectedRun}
              summary={selectedRunSummary}
            />
          ) : (
            <VpwEmptyState
              description="Select an import run to inspect parser, upload, provider, and raw metadata."
              title="No run selected"
            />
          )}
        </div>
        {selectedRunSummary ? (
          <SheetFooter className="sticky bottom-0 flex-col shrink-0 border-t border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-panel)] px-5 py-3 sm:flex-row sm:justify-between">
            <Button asChild size="sm" variant="outline">
              <Link search={{ projectId: selectedRunSummary.project_id }} to="/findings">
                Review findings
              </Link>
            </Button>
            <Button asChild size="sm">
              <Link
                params={{ runId: selectedRunSummary.id }}
                search={{ projectId: selectedRunSummary.project_id }}
                to="/imports/runs/$runId"
              >
                Open run detail
              </Link>
            </Button>
          </SheetFooter>
        ) : null}
      </SheetContent>
    </Sheet>
  )
}

function DiagnosticsTabs({
  run,
  summary,
}: {
  run: AnalysisRunPublic
  summary: AnalysisRunSummaryPublic
}) {
  const parseErrors = summary.parse_errors ?? []
  const summaryJson = objectRecord(summary.summary_json)
  const rawJson = jsonPreview({ run, summary })
  const uploadRows = metadataRows(summary.input_upload).map(([label, value]) => ({
    label,
    value: String(value),
  }))
  const providerRows = [
    {
      label: "Provider mode",
      value: stringValue(summary.input_upload, "provider_mode") ?? "Current provider data",
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
    {
      label: "Locked replay",
      value: stringValue(summary.input_upload, "locked_provider_data") ?? "Not recorded",
    },
  ]

  return (
    <Tabs defaultValue="summary">
      <TabsList
        aria-label="Run diagnostics tabs"
        className="flex w-full flex-nowrap justify-start overflow-x-auto whitespace-nowrap"
      >
        <TabsTrigger value="summary">Summary</TabsTrigger>
        <TabsTrigger value="parser">Parser</TabsTrigger>
        <TabsTrigger value="upload">Upload</TabsTrigger>
        <TabsTrigger value="provider">Provider</TabsTrigger>
        <TabsTrigger value="raw">Raw</TabsTrigger>
      </TabsList>
      <TabsContent value="summary">
        <VpwPanel className="flex flex-col gap-4">
          <CompactRows
            items={[
              {
                label: "Run ID",
                value: <CopyableValue label="Copy run ID" value={summary.id} />,
              },
              {
                label: "Status",
                value: runStatusLabel(summary.status),
              },
              {
                label: "Input type",
                value: formatDisplayType(summary.input_type),
              },
              {
                label: "Filename",
                value: runFileLabel(summary),
              },
              {
                label: "Started",
                value: formatDateTime(summary.started_at),
              },
              {
                label: "Finished",
                value: formatDateTime(summary.finished_at),
              },
              {
                label: "Created",
                value: summary.created_findings ?? 0,
              },
              {
                label: "Updated",
                value: summary.updated_findings ?? 0,
              },
              {
                label: "Ignored",
                value: summary.ignored_lines ?? 0,
              },
            ]}
          />
          {summary.status === "failed" ? (
            <VpwStatusBanner title="Failure cause" tone="critical">
              {failedRunCause(run, summary)}
            </VpwStatusBanner>
          ) : null}
        </VpwPanel>
      </TabsContent>
      <TabsContent value="parser">
        <VpwPanel className="flex flex-col gap-4">
          <CompactRows
            items={[
              { label: "Rows read", value: recordedValue(summaryJson.rows_read) },
              { label: "Created findings", value: summary.created_findings ?? 0 },
              { label: "Updated findings", value: summary.updated_findings ?? 0 },
              { label: "Finding count", value: summary.finding_count ?? 0 },
              { label: "Ignored lines", value: summary.ignored_lines ?? 0 },
              { label: "Parser errors", value: parseErrors.length },
              { label: "Warnings", value: warningCount(summaryJson) },
            ]}
          />
          {parseErrors.length > 0 ? (
            <ParserErrorsTable errors={parseErrors} />
          ) : (
            <p className="rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-3 py-2 text-sm text-[var(--vpw-text-secondary)]">
              No parser errors recorded.
            </p>
          )}
        </VpwPanel>
      </TabsContent>
      <TabsContent value="upload">
        <VpwPanel>
          {uploadRows.length > 0 ? (
            <CompactRows items={uploadRows} />
          ) : (
            <VpwEmptyState title="No upload metadata recorded" />
          )}
        </VpwPanel>
      </TabsContent>
      <TabsContent value="provider">
        <VpwPanel>
          <CompactRows items={providerRows} />
        </VpwPanel>
      </TabsContent>
      <TabsContent value="raw">
        <VpwPanel>
          <details>
            <summary className="cursor-pointer text-sm font-medium text-[var(--vpw-text-primary)]">
              Raw run metadata
            </summary>
            <pre className="mt-3 max-h-[26rem] overflow-auto rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-panel)] p-3 text-xs text-[var(--vpw-text-primary)]">
              <code>{rawJson}</code>
            </pre>
            <div className="mt-3 flex justify-end">
              <CopyButton label="Copy raw diagnostics JSON" value={rawJson} />
            </div>
          </details>
        </VpwPanel>
      </TabsContent>
    </Tabs>
  )
}
