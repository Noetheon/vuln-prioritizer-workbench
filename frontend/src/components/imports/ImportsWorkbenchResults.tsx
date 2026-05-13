import { Link } from "@/lib/router"
import { CheckCircle2 } from "lucide-react"
import type { ImportParseErrorPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwBadge,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwGrid,
  VpwMetricCard,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
} from "@/components/vpw"
import { runStatusLabel } from "@/lib/risk-format"
import { type ImportsWorkbenchProps, runTone } from "./imports-workbench-model"

export function ImportResult({
  importRun,
  importRunSummary,
}: Pick<ImportsWorkbenchProps, "importRun" | "importRunSummary">) {
  if (!importRun && !importRunSummary) return null

  const summaryRun = importRunSummary ?? importRun
  const status = summaryRun?.status ?? "pending"
  const runId = summaryRun?.id ?? importRun?.id ?? ""
  const projectId = summaryRun?.project_id ?? importRun?.project_id ?? ""
  const findingsSearch = { projectId }
  const reportsSearch = { projectId, runId }

  return (
    <VpwSection>
      <VpwSectionHeader
        actions={
          <VpwBadge tone={runTone(status)}>{runStatusLabel(status)}</VpwBadge>
        }
        description="Latest completed import result from the current session."
        title="Import Result"
      />
      <VpwPanel>
        <VpwGrid columns={4}>
          <VpwMetricCard
            description={runId ? `Run ${runId.slice(0, 8)}` : "Run pending"}
            icon={<CheckCircle2 aria-hidden="true" className="h-4 w-4" />}
            label="Run status"
            tone={runTone(status) === "critical" ? "critical" : "success"}
            value={runStatusLabel(status)}
          />
          <VpwMetricCard
            description="New findings"
            label="Created findings"
            tone="info"
            value={importRunSummary?.created_findings ?? 0}
          />
          <VpwMetricCard
            description="Existing findings"
            label="Updated findings"
            tone="support"
            value={importRunSummary?.updated_findings ?? 0}
          />
          <VpwMetricCard
            description={runId ? runId : "No run recorded"}
            label="Ignored lines"
            tone="warning"
            value={importRunSummary?.ignored_lines ?? 0}
          />
        </VpwGrid>
        {importRunSummary?.analysis_decision_scope ||
        importRunSummary?.persistence_scope ? (
          <div className="mt-4 flex flex-wrap gap-2">
            {importRunSummary.analysis_decision_scope ? (
              <VpwBadge tone="support">
                Decisions: {importRunSummary.analysis_decision_scope}
              </VpwBadge>
            ) : null}
            {importRunSummary.persistence_scope ? (
              <VpwBadge tone="info">
                Persistence: {importRunSummary.persistence_scope}
              </VpwBadge>
            ) : null}
          </div>
        ) : null}
        <div className="mt-5 flex flex-wrap gap-2">
          <Button asChild variant="outline">
            <Link search={findingsSearch} to="/findings">
              View Findings
            </Link>
          </Button>
          <Button asChild variant="outline">
            <Link search={reportsSearch} to="/reports">
              Generate Evidence
            </Link>
          </Button>
        </div>
      </VpwPanel>
    </VpwSection>
  )
}

export function ParserErrors({ errors }: { errors: ImportParseErrorPublic[] }) {
  if (errors.length === 0) return null

  const columns: VpwDataTableColumn<ImportParseErrorPublic>[] = [
    { id: "line", header: "Line", cell: (error) => error.line ?? "Not supplied" },
    { id: "field", header: "Field", cell: (error) => error.field ?? "Not supplied" },
    { id: "value", header: "Value", cell: (error) => error.value ?? "Not supplied" },
    { id: "message", header: "Message", cell: (error) => error.message },
  ]

  return (
    <VpwSection>
      <VpwSectionHeader
        actions={<VpwBadge tone="critical">{errors.length} issue(s)</VpwBadge>}
        description="Rows rejected during parser validation."
        title="Parser Errors"
      />
      <VpwDataTable
        caption="Parser errors"
        columns={columns}
        data={errors}
        getRowKey={(error, index) =>
          [error.filename, error.line, error.field, error.value, index].join(
            ":",
          )
        }
      />
    </VpwSection>
  )
}
