import { Link } from "@/lib/router"
import { History } from "lucide-react"
import type { AnalysisRunPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwBadge,
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
import { runStatusLabel } from "@/lib/risk-format"
import { ParserErrors } from "./ImportsWorkbenchResults"
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
      id: "run",
      header: "Run",
      cell: (run) => (
        <Button
          className="h-auto p-0 font-mono text-sm"
          onClick={() => onSelectRun(run.id)}
          type="button"
          variant="link"
        >
          {run.id.slice(0, 8)}
        </Button>
      ),
    },
    { id: "file", header: "Input file", cell: (run) => runFileLabel(run) },
    {
      id: "type",
      header: "Input type",
      cell: (run) => (
        <VpwBadge tone="info">{formatDisplayType(run.input_type)}</VpwBadge>
      ),
    },
    {
      id: "status",
      header: "Status",
      cell: (run) => (
        <VpwBadge tone={runTone(run.status)}>
          {runStatusLabel(run.status)}
        </VpwBadge>
      ),
    },
    {
      id: "findings",
      header: "Findings",
      cell: (run) =>
        selectedRunId === run.id && selectedRunSummary
          ? `${selectedRunSummary.created_findings ?? 0} created / ${
              selectedRunSummary.updated_findings ?? 0
            } updated`
          : "Select for counts",
    },
    {
      id: "started",
      header: "Timestamp",
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
      {runsLoading ? (
        <VpwPanel>
          <VpwSkeletonStack rows={4} />
        </VpwPanel>
      ) : (
        <VpwDataTable
          caption="Recent import runs"
          columns={columns}
          data={projectRuns}
          emptyState={
            <VpwEmptyState
              description="Upload a supported file to create import run history."
              icon={<History aria-hidden="true" className="h-5 w-5" />}
              title="No import runs yet"
            />
          }
          getRowKey={(run) => run.id}
        />
      )}
      <RunDetail
        runDetailError={runDetailError}
        runDetailLoading={runDetailLoading}
        selectedRun={selectedRun}
        selectedRunId={selectedRunId}
        selectedRunSummary={selectedRunSummary}
      />
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
              Findings
            </Link>
          </Button>
          <Button asChild size="sm" variant="outline">
            <Link search={reportsSearch} to="/reports">
              Evidence
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
        <ParserErrors errors={selectedParseErrors} />
      ) : (
        <VpwEmptyState title="No parser errors recorded" />
      )}
    </VpwPanel>
  )
}
