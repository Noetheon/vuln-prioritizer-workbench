import type { AnalysisRunPublic, AnalysisRunSummaryPublic } from "@/api-client"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  VpwEmptyState,
  VpwPanel,
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
  runCount,
  runFileLabel,
  runInputUpload,
  runLockedProviderData,
} from "./imports-workbench-model"

type ImportDiagnosticsDrawerTabsProps = {
  run: AnalysisRunPublic
  summary: AnalysisRunSummaryPublic
}

export function ImportDiagnosticsDrawerTabs({
  run,
  summary,
}: ImportDiagnosticsDrawerTabsProps) {
  const parseErrors = summary.parse_errors ?? []
  const rawJson = jsonPreview({ run, summary })
  const inputUpload = runInputUpload(summary)
  const uploadRows = metadataRows(inputUpload).map(([label, value]) => ({
    label,
    value: String(value),
  }))
  const providerRows = [
    {
      label: "Provider mode",
      value: stringValue(inputUpload, "provider_mode") ?? "Current provider data",
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
      value:
        booleanLabel(runLockedProviderData(summary)) ??
        stringValue(inputUpload, "locked_provider_data") ??
        "Not recorded",
    },
  ]

  return (
    <Tabs defaultValue="summary">
      <TabsList
        aria-label="Run diagnostics tabs"
        className="grid h-auto w-full grid-cols-5 overflow-visible whitespace-nowrap sm:inline-flex sm:w-auto sm:justify-start"
      >
        <TabsTrigger className="min-w-0 px-1.5 text-xs sm:px-3 sm:text-sm" value="summary">
          Summary
        </TabsTrigger>
        <TabsTrigger className="min-w-0 px-1.5 text-xs sm:px-3 sm:text-sm" value="parser">
          Parser
        </TabsTrigger>
        <TabsTrigger className="min-w-0 px-1.5 text-xs sm:px-3 sm:text-sm" value="upload">
          Upload
        </TabsTrigger>
        <TabsTrigger className="min-w-0 px-1.5 text-xs sm:px-3 sm:text-sm" value="provider">
          Provider
        </TabsTrigger>
        <TabsTrigger className="min-w-0 px-1.5 text-xs sm:px-3 sm:text-sm" value="raw">
          Raw
        </TabsTrigger>
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
                value: runCount(summary, "created_findings"),
              },
              {
                label: "Updated",
                value: runCount(summary, "updated_findings"),
              },
              {
                label: "Ignored",
                value: runCount(summary, "ignored_lines"),
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
              { label: "Parser status", value: runStatusLabel(summary.status) },
              { label: "Rows read", value: recordedValue(runCount(summary, "rows_read")) },
              { label: "Created findings", value: runCount(summary, "created_findings") },
              { label: "Updated findings", value: runCount(summary, "updated_findings") },
              { label: "Finding count", value: runCount(summary, "finding_count") },
              { label: "Ignored lines", value: runCount(summary, "ignored_lines") },
              { label: "Parser errors", value: parseErrors.length },
              { label: "Warnings", value: warningCount(summary.warnings) },
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

function booleanLabel(value: boolean | null | undefined) {
  if (typeof value !== "boolean") return null
  return value ? "Yes" : "No"
}
