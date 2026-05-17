import { Link } from "@/lib/router"
import type { AnalysisRunPublic, AnalysisRunSummaryPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  VpwEmptyState,
  VpwKeyValueList,
  VpwPanel,
  VpwSkeletonStack,
  VpwStatusBanner,
} from "@/components/vpw"
import { runStatusLabel } from "@/lib/risk-format"
import { ParserErrorsTable } from "./ImportsWorkbenchResults"
import {
  failedRunCause,
  formatDateTime,
  formatDisplayType,
  jsonPreview,
  metadataRows,
  objectRecord,
  runFileLabel,
  runTone,
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
      <SheetContent className="vpw-sheet-content w-full overflow-y-auto max-sm:left-0 max-sm:right-0 max-sm:w-auto max-sm:max-w-none sm:max-w-2xl">
        <SheetHeader>
          <SheetTitle>Run diagnostics</SheetTitle>
          <SheetDescription>
            Run ID {diagnosticsRunId ? diagnosticsRunId.slice(0, 8) : "not selected"}
          </SheetDescription>
        </SheetHeader>
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
      value: summary.provider_snapshot_id ?? "Not recorded",
    },
    {
      label: "Locked replay",
      value: stringValue(summary.input_upload, "locked_provider_data") ?? "Not recorded",
    },
  ]

  return (
    <Tabs className="mt-5" defaultValue="summary">
      <TabsList aria-label="Run diagnostics tabs" className="flex flex-wrap justify-start">
        <TabsTrigger value="summary">Summary</TabsTrigger>
        <TabsTrigger value="parser">Parser</TabsTrigger>
        <TabsTrigger value="upload">Upload</TabsTrigger>
        <TabsTrigger value="provider">Provider</TabsTrigger>
        <TabsTrigger value="raw">Raw</TabsTrigger>
      </TabsList>
      <TabsContent value="summary">
        <VpwPanel className="flex flex-col gap-4">
          <VpwKeyValueList
            columns={2}
            items={[
              {
                label: "Run ID",
                value: summary.id,
              },
              {
                label: "Status",
                value: runStatusLabel(summary.status),
                tone: runTone(summary.status),
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
          <div className="flex flex-wrap gap-2">
            <Button asChild size="sm" variant="outline">
              <Link search={{ projectId: summary.project_id }} to="/findings">
                Review findings
              </Link>
            </Button>
            <Button asChild size="sm">
              <Link
                params={{ runId: summary.id }}
                search={{ projectId: summary.project_id }}
                to="/imports/runs/$runId"
              >
                Open run detail
              </Link>
            </Button>
          </div>
        </VpwPanel>
      </TabsContent>
      <TabsContent value="parser">
        <VpwPanel className="flex flex-col gap-4">
          <VpwKeyValueList
            columns={2}
            items={[
              { label: "Created findings", value: summary.created_findings ?? 0 },
              { label: "Updated findings", value: summary.updated_findings ?? 0 },
              { label: "Finding count", value: summary.finding_count ?? 0 },
              { label: "Ignored lines", value: summary.ignored_lines ?? 0 },
              { label: "Parser errors", value: parseErrors.length },
            ]}
          />
          {parseErrors.length > 0 ? (
            <ParserErrorsTable errors={parseErrors} />
          ) : (
            <VpwEmptyState title="No parser errors recorded" />
          )}
        </VpwPanel>
      </TabsContent>
      <TabsContent value="upload">
        <VpwPanel>
          {uploadRows.length > 0 ? (
            <VpwKeyValueList columns={2} items={uploadRows} />
          ) : (
            <VpwEmptyState title="No upload metadata recorded" />
          )}
        </VpwPanel>
      </TabsContent>
      <TabsContent value="provider">
        <VpwPanel>
          <VpwKeyValueList columns={2} items={providerRows} />
        </VpwPanel>
      </TabsContent>
      <TabsContent value="raw">
        <VpwPanel>
          <details>
            <summary className="cursor-pointer text-sm font-medium text-[var(--vpw-text-primary)]">
              Raw run metadata
            </summary>
            <pre className="mt-3 max-h-[26rem] overflow-auto rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-panel)] p-3 text-xs text-[var(--vpw-text-primary)]">
              <code>{jsonPreview({ run, summary })}</code>
            </pre>
          </details>
        </VpwPanel>
      </TabsContent>
    </Tabs>
  )
}

function stringValue(source: unknown, key: string) {
  const record = objectRecord(source)
  const value = record[key]
  if (typeof value === "string" && value.trim()) return value
  if (typeof value === "boolean") return value ? "Yes" : "No"
  return null
}
