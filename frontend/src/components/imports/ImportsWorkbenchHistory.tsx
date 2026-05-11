import { Link } from "@tanstack/react-router"
import { History } from "lucide-react"
import type { AnalysisRunPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwBadge,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwSkeletonStack,
  VpwStatusBanner,
} from "@/components/vpw"
import { runStatusLabel } from "@/lib/risk-format"
import { ParserErrors } from "./ImportsWorkbenchResults"
import {
  failedRunCause,
  formatDateTime,
  formatDisplayType,
  type ImportsWorkbenchProps,
  jsonPreview,
  metadataRows,
  objectRecord,
  runFileLabel,
  runTone,
} from "./imports-workbench-model"

export function RecentImports({
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
>) {
  const columns: VpwDataTableColumn<AnalysisRunPublic>[] = [
    {
      id: "source",
      header: "Source",
      cell: (run) => (
        <div className="imports-run-source">
          <button onClick={() => onSelectRun(run.id)} type="button">
            {runFileLabel(run)}
          </button>
          <span>Run {run.id.slice(0, 8)}</span>
        </div>
      ),
    },
    {
      id: "parser",
      header: "Parser",
      cell: (run) => (
        <VpwBadge tone="info">{formatDisplayType(run.input_type)}</VpwBadge>
      ),
    },
    {
      id: "result",
      header: "Result",
      cell: (run) => (
        <div className="imports-run-result">
          <VpwBadge tone={runTone(run.status)}>
            {runStatusLabel(run.status)}
          </VpwBadge>
          <span>{runCountLabel(run, selectedRunId, selectedRunSummary)}</span>
        </div>
      ),
    },
    {
      id: "started",
      header: "Time",
      cell: (run) => formatDateTime(run.started_at),
    },
    {
      id: "actions",
      header: "Actions",
      className: "text-right",
      headerClassName: "text-right",
      cell: (run) => (
        <Button
          onClick={() => onSelectRun(run.id)}
          size="sm"
          type="button"
          variant={selectedRunId === run.id ? "default" : "outline"}
        >
          {selectedRunId === run.id ? "Selected" : "Inspect"}
        </Button>
      ),
    },
  ]

  return (
    <VpwSection>
      <VpwSectionHeader
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
      />
      {runsError ? (
        <VpwStatusBanner title="Import runs unavailable" tone="critical">
          {runsError}
        </VpwStatusBanner>
      ) : null}
      <div className="imports-history-shell">
        <div className="min-w-0">
          {runsLoading ? (
            <VpwPanel>
              <VpwSkeletonStack rows={4} />
            </VpwPanel>
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
              minWidth="820px"
            />
          )}
        </div>
        <RunDetail
          runDetailError={runDetailError}
          runDetailLoading={runDetailLoading}
          selectedRun={selectedRun}
          selectedRunId={selectedRunId}
          selectedRunSummary={selectedRunSummary}
        />
      </div>
    </VpwSection>
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
  const stats = [
    ["Created", selectedRunSummary.created_findings ?? 0],
    ["Updated", selectedRunSummary.updated_findings ?? 0],
    ["Findings", selectedRunSummary.finding_count ?? 0],
    ["Ignored", selectedRunSummary.ignored_lines ?? 0],
  ] as const

  return (
    <VpwPanel className="imports-run-detail">
      <div className="imports-run-detail-header">
        <div>
          <p className="imports-kicker">Run detail</p>
          <h3>{selectedRunId.slice(0, 8)}</h3>
        </div>
        <Button asChild size="sm" variant="outline">
          <Link to="/findings">Findings</Link>
        </Button>
      </div>
      <dl className="imports-run-detail-summary">
        <div className="imports-run-summary-row">
          <dt>Status</dt>
          <dd>
            <VpwBadge tone={runTone(selectedRunSummary.status)}>
              {runStatusLabel(selectedRunSummary.status)}
            </VpwBadge>
          </dd>
        </div>
        <div className="imports-run-summary-row">
          <dt>Parser</dt>
          <dd>{formatDisplayType(selectedRunSummary.input_type)}</dd>
        </div>
        <div className="imports-run-summary-row">
          <dt>Input</dt>
          <dd>{runFileLabel(selectedRunSummary)}</dd>
        </div>
        <div className="imports-run-summary-row">
          <dt>Started</dt>
          <dd>{formatDateTime(selectedRunSummary.started_at)}</dd>
        </div>
      </dl>
      <dl className="imports-run-stats">
        {stats.map(([label, value]) => (
          <div className="imports-run-stat" key={label}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
      {selectedRunSummary.status === "failed" ? (
        <VpwStatusBanner title="Failure Cause" tone="critical">
          <p>{failedRunCause(selectedRun, selectedRunSummary)}</p>
          <pre className="mt-3 max-h-64 overflow-auto rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-card)] p-3 text-xs">
            {jsonPreview(selectedRunSummary.error_json)}
          </pre>
        </VpwStatusBanner>
      ) : null}
      <details className="imports-technical-details">
        <summary>Technical metadata</summary>
        {metadata.length > 0 ? (
          <dl>
            {metadata.map((item) => (
              <div key={item.label}>
                <dt>{item.label}</dt>
                <dd>{item.value}</dd>
              </div>
            ))}
          </dl>
        ) : (
          <p>No upload metadata recorded.</p>
        )}
      </details>
      <details className="imports-technical-details">
        <summary>
          Parser errors{" "}
          {selectedParseErrors.length > 0
            ? `(${selectedParseErrors.length})`
            : "(none)"}
        </summary>
        {selectedParseErrors.length > 0 ? (
          <ParserErrors errors={selectedParseErrors} />
        ) : (
          <p>No parser errors recorded.</p>
        )}
      </details>
    </VpwPanel>
  )
}

function runCountLabel(
  run: AnalysisRunPublic,
  selectedRunId: string,
  selectedRunSummary: ImportsWorkbenchProps["selectedRunSummary"],
) {
  const summary =
    selectedRunId === run.id && selectedRunSummary
      ? selectedRunSummary
      : objectRecord(run.summary_json)
  const created = Number(summary.created_findings ?? 0)
  const updated = Number(summary.updated_findings ?? 0)
  if (created === 0 && updated === 0) return "No finding changes"
  return `${created} created / ${updated} updated`
}
