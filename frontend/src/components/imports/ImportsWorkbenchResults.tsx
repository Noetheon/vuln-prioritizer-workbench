import { Link } from "@tanstack/react-router"
import type { ImportParseErrorPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwBadge,
  VpwDataTable,
  type VpwDataTableColumn,
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
  const stats = [
    {
      label: "Created",
      value: importRunSummary?.created_findings ?? 0,
      tone: "info" as const,
    },
    {
      label: "Updated",
      value: importRunSummary?.updated_findings ?? 0,
      tone: "support" as const,
    },
    {
      label: "Ignored",
      value: importRunSummary?.ignored_lines ?? 0,
      tone: "warning" as const,
    },
  ]

  return (
    <VpwSection className="imports-result-section">
      <section className="imports-result-panel">
        <div className="imports-result-copy">
          <p className="imports-kicker">Import result</p>
          <h2>{runId ? `Run ${runId.slice(0, 8)}` : "Run pending"}</h2>
          <VpwBadge tone={runTone(status)}>{runStatusLabel(status)}</VpwBadge>
        </div>
        <dl className="imports-result-stats">
          {stats.map((item) => (
            <div className="imports-result-stat" key={item.label}>
              <dt>{item.label}</dt>
              <dd>
                <VpwBadge tone={item.tone}>{item.value}</VpwBadge>
              </dd>
            </div>
          ))}
        </dl>
        <div className="imports-result-actions">
          <Button asChild variant="outline">
            <Link to="/findings">View findings</Link>
          </Button>
          <Button asChild variant="outline">
            <Link to="/reports">Generate evidence</Link>
          </Button>
        </div>
        {importRunSummary?.analysis_decision_scope ||
        importRunSummary?.persistence_scope ? (
          <div className="imports-result-evidence">
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
      </section>
    </VpwSection>
  )
}

export function ParserErrors({ errors }: { errors: ImportParseErrorPublic[] }) {
  if (errors.length === 0) return null

  const columns: VpwDataTableColumn<ImportParseErrorPublic>[] = [
    { id: "line", header: "Line", cell: (error) => error.line ?? "N.A." },
    { id: "field", header: "Field", cell: (error) => error.field ?? "N.A." },
    { id: "value", header: "Value", cell: (error) => error.value ?? "N.A." },
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
