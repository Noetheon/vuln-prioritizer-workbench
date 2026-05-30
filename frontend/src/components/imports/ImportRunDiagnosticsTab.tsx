import { runStatusLabel } from "@/lib/risk-format"
import {
  VpwPanel,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import { ParserErrorsTable } from "./ImportsWorkbenchResults"
import {
  failedRunCause,
  formatDisplayType,
  jsonPreview,
  runInputUpload,
  runProviderSnapshotFile,
  runFileLabel,
} from "./imports-workbench-model"
import {
  CopyableValue,
  CopyButton,
  recordedValue,
  warningCount,
} from "./ImportDiagnosticsDrawerParts"
import {
  candidateFindings,
  numberFromSummary,
  RunDetailRows,
  stringFromRecord,
  type ImportRun,
  type ImportRunSummary,
} from "./ImportRunDetailTabShared"

export function DiagnosticsTab({
  run,
  summary,
}: {
  run: ImportRun
  summary: ImportRunSummary
}) {
  const parseErrors = summary.parse_errors ?? []
  const inputUpload = runInputUpload(summary)
  const warnings = summary.warnings ?? []
  const rawJson = jsonPreview({ run, summary })
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(360px,0.85fr)]">
      <VpwPanel className="flex flex-col gap-4">
        <VpwSectionHeader title="Parser diagnostics" />
        <RunDetailRows
          items={[
            { label: "Status", value: runStatusLabel(summary.status) },
            { label: "Rows read", value: recordedValue(numberFromSummary(summary, "rows_read")) },
            { label: "Candidate findings", value: candidateFindings(summary) },
            { label: "Findings created", value: summary.created_findings ?? 0 },
            { label: "Findings updated", value: summary.updated_findings ?? 0 },
            { label: "Ignored lines", value: summary.ignored_lines ?? 0 },
            { label: "Parser errors", value: parseErrors.length },
            { label: "Warnings", value: warningCount(warnings) },
          ]}
        />
        <div className="flex flex-col gap-3">
          <h3 className="text-sm font-medium text-[var(--vpw-text-primary)]">
            Parser messages
          </h3>
          {parseErrors.length > 0 ? (
            <ParserErrorsTable errors={parseErrors} />
          ) : (
            <p className="rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-3 py-2 text-sm text-[var(--vpw-text-secondary)]">
              No parser errors recorded.
            </p>
          )}
          {warnings.length > 0 ? (
            <ul className="grid gap-2 text-sm text-[var(--vpw-text-secondary)]">
              {warnings.map((warning) => (
                <li
                  className="rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-3 py-2"
                  key={warning}
                >
                  {warning}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      </VpwPanel>
      <div className="grid gap-4">
        <VpwPanel className="flex flex-col gap-4">
          <VpwSectionHeader title="Upload and provider" />
          <RunDetailRows
            items={[
              { label: "Filename", value: runFileLabel(summary) },
              { label: "Input type", value: formatDisplayType(summary.input_type) },
              {
                label: "File hash",
                value: stringFromRecord(inputUpload, "sha256") ? (
                  <CopyableValue
                    label="Copy file hash"
                    value={stringFromRecord(inputUpload, "sha256") ?? ""}
                  />
                ) : (
                  "Not recorded"
                ),
              },
              {
                label: "Storage reference",
                value: stringFromRecord(inputUpload, "storage_ref") ? (
                  <CopyableValue
                    label="Copy storage reference"
                    value={stringFromRecord(inputUpload, "storage_ref") ?? ""}
                  />
                ) : (
                  "Not recorded"
                ),
              },
              {
                label: "Provider data",
                value:
                  runProviderSnapshotFile(summary) ??
                  stringFromRecord(inputUpload, "provider_snapshot_file") ??
                  "Current provider data",
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
            ]}
          />
        </VpwPanel>
        <VpwPanel>
          <details>
            <summary className="cursor-pointer text-sm font-medium text-[var(--vpw-text-primary)]">
              Raw diagnostics
            </summary>
            <div className="mt-3 flex justify-end">
              <CopyButton label="Copy diagnostics JSON" value={rawJson} />
            </div>
            <pre className="mt-3 max-h-[20rem] overflow-auto rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-panel)] p-3 text-xs text-[var(--vpw-text-primary)]">
              <code>{rawJson}</code>
            </pre>
          </details>
        </VpwPanel>
      </div>
      {summary.status === "failed" ? (
        <VpwStatusBanner title="Failure cause" tone="critical">
          {failedRunCause(run, summary)}
        </VpwStatusBanner>
      ) : null}
    </div>
  )
}
