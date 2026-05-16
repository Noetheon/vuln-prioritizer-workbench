import { Link } from "@/lib/router"
import { FileSearch, History, ListChecks } from "lucide-react"
import type { ReactNode } from "react"
import type { AnalysisRunPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  MetaTag,
  SourceMark,
  StatusLozenge,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwSection,
  VpwSkeletonStack,
  VpwStatusBanner,
  VpwTableCard,
} from "@/components/vpw"
import { runStatusLabel } from "@/lib/risk-format"
import { RunDiagnosticsSheet } from "./ImportsWorkbenchRunDetail"
import {
  formatDateTime,
  formatDisplayType,
  type ImportsWorkbenchProps,
  objectRecord,
  runFileLabel,
} from "./imports-workbench-model"

function ImportRunAction({
  children,
  label,
}: {
  children: ReactNode
  label: string
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}

export function RecentImports({
  diagnosticsOpen,
  diagnosticsRunId,
  onDiagnosticsOpenChange,
  onOpenDiagnostics,
  onRefreshRuns,
  onSelectRun,
  projectRuns,
  runDetailError,
  runDetailLoading,
  runsError,
  runsLoading,
  selectedProject,
  selectedRun,
  selectedRunId,
  selectedRunSummary,
}: Pick<
  ImportsWorkbenchProps,
  | "onRefreshRuns"
  | "onSelectRun"
  | "projectRuns"
  | "runDetailError"
  | "runDetailLoading"
  | "runsError"
  | "runsLoading"
  | "selectedProject"
  | "selectedRun"
  | "selectedRunId"
  | "selectedRunSummary"
> & {
  diagnosticsOpen: boolean
  diagnosticsRunId: string
  onDiagnosticsOpenChange: (open: boolean) => void
  onOpenDiagnostics: (runId: string) => void
}) {
  function findingsLabel(run: AnalysisRunPublic) {
    if (selectedRunId === run.id && selectedRunSummary) {
      const count =
        selectedRunSummary.finding_count ??
        (selectedRunSummary.created_findings ?? 0) +
          (selectedRunSummary.updated_findings ?? 0)
      return `${count} finding(s)`
    }
    const summary = objectRecord(run.summary_json)
    const count = summary.finding_count
    return typeof count === "number" ? `${count} finding(s)` : "Open for counts"
  }

  const columns: VpwDataTableColumn<AnalysisRunPublic>[] = [
    {
      id: "run",
      header: "Run",
      cell: (run) => (
        <div className="min-w-0">
          <Button
            className="h-auto p-0 font-mono text-sm"
            onClick={() => onSelectRun(run.id)}
            type="button"
            variant="link"
          >
            {run.id.slice(0, 8)}
          </Button>
          <span className="vpw-table-subtext">
            {formatDateTime(run.started_at)}
          </span>
        </div>
      ),
    },
    {
      id: "source",
      header: "Source",
      cell: (run) => (
        <div className="flex min-w-0 flex-col gap-1">
          <span className="font-medium text-[var(--vpw-text-primary)]">
            {runFileLabel(run)}
          </span>
          <MetaTag label={formatDisplayType(run.input_type)} />
        </div>
      ),
    },
    {
      id: "status",
      header: "Status",
      cell: (run) => (
        <StatusLozenge
          density="compact"
          label={runStatusLabel(run.status)}
          status={run.status}
        />
      ),
    },
    {
      id: "findings",
      header: "Findings",
      cell: findingsLabel,
    },
    {
      id: "provider",
      header: "Provider snapshot",
      cell: (run) =>
        run.provider_snapshot_id ? (
          <SourceMark label={run.provider_snapshot_id} source="provider" />
        ) : (
          <span className="text-[var(--vpw-text-muted)]">Not recorded</span>
        ),
    },
    {
      id: "actions",
      header: "Actions",
      className: "text-right",
      headerClassName: "text-right",
      cell: (run) => (
        <div className="vpw-table-actions">
          <ImportRunAction label="View diagnostics">
            <Button
              aria-label={`View diagnostics for run ${run.id.slice(0, 8)}`}
              className="vpw-table-action-button"
              onClick={() => onOpenDiagnostics(run.id)}
              size="icon-sm"
              type="button"
              variant="outline"
            >
              <FileSearch aria-hidden="true" />
            </Button>
          </ImportRunAction>
          <ImportRunAction label="Review findings">
            <Button
              asChild
              className="vpw-table-action-button"
              size="icon-sm"
              variant="outline"
            >
              <Link
                aria-label={`Review findings for run ${run.id.slice(0, 8)}`}
                search={{ projectId: run.project_id }}
                to="/findings"
              >
                <ListChecks aria-hidden="true" />
              </Link>
            </Button>
          </ImportRunAction>
        </div>
      ),
    },
  ]

  return (
    <VpwSection>
      <VpwTableCard
        actions={
          <Button
            disabled={runsLoading || !selectedProject}
            onClick={onRefreshRuns}
            size="sm"
            type="button"
            variant="outline"
          >
            Refresh
          </Button>
        }
        description={selectedProject?.name ?? "No project selected"}
        title="Recent Imports"
      >
        {runsError ? (
          <VpwStatusBanner title="Import runs unavailable" tone="critical">
            {runsError}
          </VpwStatusBanner>
        ) : null}
        {runsLoading ? (
          <VpwSkeletonStack rows={4} />
        ) : (
          <VpwDataTable
            caption="Recent import runs"
            columns={columns}
            data={projectRuns}
            density="compact"
            emptyState={
              <VpwEmptyState
                description="Upload a supported file to create import run history."
                icon={<History aria-hidden="true" className="h-5 w-5" />}
                title="No import runs yet"
              />
            }
            getRowKey={(run) => run.id}
            minWidth="960px"
          />
        )}
      </VpwTableCard>
      <RunDiagnosticsSheet
        diagnosticsOpen={diagnosticsOpen}
        diagnosticsRunId={diagnosticsRunId}
        onDiagnosticsOpenChange={onDiagnosticsOpenChange}
        runDetailError={runDetailError}
        runDetailLoading={runDetailLoading}
        selectedRun={selectedRun}
        selectedRunId={selectedRunId}
        selectedRunSummary={selectedRunSummary}
      />
    </VpwSection>
  )
}
