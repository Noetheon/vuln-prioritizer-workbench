import { Link } from "@/lib/router"
import { Button } from "@/components/ui/button"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import {
  VpwBadge,
  VpwEmptyState,
  VpwGrid,
  VpwKeyValueList,
  VpwMetricCard,
  VpwPanel,
  VpwSectionHeader,
  VpwSkeletonStack,
  VpwStatusBanner,
} from "@/components/vpw"
import { runStatusLabel } from "@/lib/risk-format"
import { ParserErrorsTable } from "./ImportsWorkbenchResults"
import {
  failedRunCause,
  formatDateTime,
  formatDisplayType,
  type ImportsWorkbenchProps,
  jsonPreview,
  metadataRows,
  runFileLabel,
  runTone,
} from "./imports-workbench-model"

export function RunDiagnosticsSheet({
  diagnosticsOpen,
  diagnosticsRunId,
  onDiagnosticsOpenChange,
  runDetailError,
  runDetailLoading,
  selectedRun,
  selectedRunId,
  selectedRunSummary,
}: Pick<
  ImportsWorkbenchProps,
  | "runDetailError"
  | "runDetailLoading"
  | "selectedRun"
  | "selectedRunId"
  | "selectedRunSummary"
> & {
  diagnosticsOpen: boolean
  diagnosticsRunId: string
  onDiagnosticsOpenChange: (open: boolean) => void
}) {
  const waitingForSelectedRun = Boolean(
    diagnosticsRunId && selectedRunId !== diagnosticsRunId,
  )

  return (
    <Sheet open={diagnosticsOpen} onOpenChange={onDiagnosticsOpenChange}>
      <SheetContent className="vpw-sheet-content w-full overflow-y-auto sm:max-w-2xl">
        <SheetHeader>
          <SheetTitle>Run diagnostics</SheetTitle>
          <SheetDescription>
            Parser, upload, provider snapshot, and result evidence for the
            selected import run.
          </SheetDescription>
        </SheetHeader>
        {waitingForSelectedRun ? (
          <VpwPanel>
            <VpwSkeletonStack rows={4} />
          </VpwPanel>
        ) : (
          <RunDetail
            runDetailError={runDetailError}
            runDetailLoading={runDetailLoading}
            selectedRun={selectedRun}
            selectedRunId={selectedRunId}
            selectedRunSummary={selectedRunSummary}
          />
        )}
      </SheetContent>
    </Sheet>
  )
}

export function RunDetail({
  runDetailError,
  runDetailLoading,
  selectedRun,
  selectedRunId,
  selectedRunSummary,
}: Pick<
  ImportsWorkbenchProps,
  | "runDetailError"
  | "runDetailLoading"
  | "selectedRun"
  | "selectedRunId"
  | "selectedRunSummary"
>) {
  if (runDetailLoading) {
    return (
      <VpwPanel>
        <VpwSkeletonStack rows={4} />
      </VpwPanel>
    )
  }

  if (runDetailError) {
    return (
      <VpwStatusBanner title="Run detail unavailable" tone="critical">
        {runDetailError}
      </VpwStatusBanner>
    )
  }

  if (!selectedRunId) {
    return (
      <VpwEmptyState
        description="Select a historical import run to inspect details."
        title="No run selected"
      />
    )
  }

  if (!selectedRun || !selectedRunSummary) return null

  const metadata = metadataRows(selectedRunSummary.input_upload).map(
    ([label, value]) => ({
      label,
      value: String(value),
    }),
  )
  const selectedParseErrors = selectedRunSummary.parse_errors ?? []
  const findingsSearch = { projectId: selectedRunSummary.project_id }
  const reportsSearch = {
    projectId: selectedRunSummary.project_id,
    runId: selectedRunSummary.id,
  }

  return (
    <VpwPanel className="flex flex-col gap-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="vpw-label">Run detail</p>
          <h3 className="mt-1 text-lg font-semibold text-[var(--vpw-text-primary)]">
            {selectedRunId.slice(0, 8)}
          </h3>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button asChild size="sm" variant="outline">
            <Link search={findingsSearch} to="/findings">
              Review findings
            </Link>
          </Button>
          <Button asChild size="sm" variant="outline">
            <Link search={reportsSearch} to="/reports">
              Evidence Center
            </Link>
          </Button>
        </div>
      </div>
      <VpwKeyValueList
        columns={2}
        items={[
          {
            label: "Status",
            value: runStatusLabel(selectedRunSummary.status),
            tone: runTone(selectedRunSummary.status),
          },
          {
            label: "Input type",
            value: formatDisplayType(selectedRunSummary.input_type),
          },
          { label: "Filename", value: runFileLabel(selectedRunSummary) },
          {
            label: "Started",
            value: formatDateTime(selectedRunSummary.started_at),
          },
          {
            label: "Finished",
            value: formatDateTime(selectedRunSummary.finished_at),
          },
          {
            label: "Provider snapshot",
            value: selectedRunSummary.provider_snapshot_id ?? "Not recorded",
          },
        ]}
      />
      <VpwGrid columns={4}>
        <VpwMetricCard
          label="Created"
          value={selectedRunSummary.created_findings ?? 0}
        />
        <VpwMetricCard
          label="Updated"
          value={selectedRunSummary.updated_findings ?? 0}
        />
        <VpwMetricCard
          label="Findings"
          value={selectedRunSummary.finding_count ?? 0}
        />
        <VpwMetricCard
          label="Ignored"
          value={selectedRunSummary.ignored_lines ?? 0}
        />
      </VpwGrid>
      {selectedRunSummary.status === "failed" ? (
        <VpwStatusBanner title="Failure Cause" tone="critical">
          <p>{failedRunCause(selectedRun, selectedRunSummary)}</p>
          <pre className="mt-3 whitespace-pre-wrap break-words rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-card)] p-3 text-xs">
            <code>{jsonPreview(selectedRunSummary.error_json)}</code>
          </pre>
        </VpwStatusBanner>
      ) : null}
      <VpwSectionHeader title="Upload Metadata" />
      {metadata.length > 0 ? (
        <VpwKeyValueList columns={2} items={metadata} />
      ) : (
        <VpwEmptyState title="No upload metadata recorded" />
      )}
      <VpwSectionHeader
        actions={
          selectedParseErrors.length > 0 ? (
            <VpwBadge tone="critical">
              {selectedParseErrors.length} parser issue(s)
            </VpwBadge>
          ) : (
            <VpwBadge tone="success">No parser errors</VpwBadge>
          )
        }
        title="Run Parser Errors"
      />
      {selectedParseErrors.length > 0 ? (
        <ParserErrorsTable errors={selectedParseErrors} />
      ) : (
        <VpwEmptyState title="No parser errors recorded" />
      )}
    </VpwPanel>
  )
}
