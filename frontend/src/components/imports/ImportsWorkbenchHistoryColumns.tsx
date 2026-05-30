import type { AnalysisRunPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  MetaTag,
  SourceMark,
  StatusLozenge,
  type VpwDataTableColumn,
} from "@/components/vpw"
import { runStatusLabel } from "@/lib/risk-format"
import {
  formatDateTime,
  formatDisplayType,
  type ImportsWorkbenchProps,
  runCount,
  runFileLabel,
} from "./imports-workbench-model"
import { ImportRunActions } from "./ImportsWorkbenchHistoryActions"

type BuildImportHistoryColumnsArgs = Pick<
  ImportsWorkbenchProps,
  "onSelectRun" | "selectedRunId" | "selectedRunSummary"
> & {
  onOpenDiagnostics: (runId: string) => void
}

export function buildImportHistoryColumns({
  onOpenDiagnostics,
  onSelectRun,
  selectedRunId,
  selectedRunSummary,
}: BuildImportHistoryColumnsArgs): VpwDataTableColumn<AnalysisRunPublic>[] {
  function findingsLabel(run: AnalysisRunPublic) {
    if (selectedRunId === run.id && selectedRunSummary) {
      const count =
        selectedRunSummary.finding_count ??
        (selectedRunSummary.created_findings ?? 0) +
          (selectedRunSummary.updated_findings ?? 0)
      return `${count} finding(s)`
    }
    const count = runCount(run, "finding_count")
    return typeof count === "number" ? `${count} finding(s)` : "Open for counts"
  }

  function runNumber(
    run: AnalysisRunPublic,
    key: "created_findings" | "updated_findings" | "ignored_lines",
  ) {
    if (selectedRunId === run.id && selectedRunSummary) {
      const value = selectedRunSummary[key]
      return typeof value === "number" ? value : 0
    }
    return runCount(run, key)
  }

  return [
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
      id: "created",
      header: "Created",
      cell: (run) => runNumber(run, "created_findings"),
    },
    {
      id: "updated",
      header: "Updated",
      cell: (run) => runNumber(run, "updated_findings"),
    },
    {
      id: "ignored",
      header: "Ignored",
      cell: (run) => runNumber(run, "ignored_lines"),
    },
    {
      id: "provider",
      header: "Provider",
      cell: (run) =>
        run.provider_snapshot_id ? (
          <span title={run.provider_snapshot_id}>
            <SourceMark
              label={shortSnapshotLabel(run.provider_snapshot_id)}
              source="provider"
            />
          </span>
        ) : (
          <span className="text-[var(--vpw-text-muted)]">Current</span>
        ),
    },
    {
      id: "actions",
      header: "Actions",
      className: "text-right",
      headerClassName: "text-right",
      cell: (run) => (
        <ImportRunActions
          onOpenDiagnostics={onOpenDiagnostics}
          run={run}
        />
      ),
    },
  ]
}

function shortSnapshotLabel(value: string) {
  const trimmed = value.trim()
  if (trimmed.length <= 12) return trimmed
  return `${trimmed.slice(0, 8)}...`
}
