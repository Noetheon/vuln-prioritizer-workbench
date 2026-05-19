import { Link } from "@/lib/router"
import { AlertCircle, ExternalLink } from "lucide-react"
import { Button } from "@/components/ui/button"
import type { ImportsWorkbenchProps } from "./imports-workbench-model"

export function ImportFailurePanel({
  failedImportRunId,
  importWizard,
  importError,
  selectedProjectId,
}: {
  failedImportRunId: string
  importWizard: ImportsWorkbenchProps["importWizard"]
  importError: string
  selectedProjectId: string
}) {
  const rows = [
    { label: "Run ID", value: failedImportRunId || "Not recorded" },
    { label: "Status", value: "failed" },
    { label: "Input type", value: importWizard.inputType || "Not selected" },
    { label: "Filename", value: importWizard.file?.name ?? "Not recorded" },
    { label: "Parser error", value: importError },
    {
      label: "Next step",
      value: failedImportRunId
        ? "Open diagnostics or inspect the recorded run."
        : "Back to file or retry the import.",
    },
  ]
  return (
    <div
      className="grid gap-5 rounded-[var(--vpw-radius-lg)] border border-[color-mix(in_srgb,var(--vpw-red)_58%,var(--vpw-border-default))] bg-[color-mix(in_srgb,var(--vpw-bg-critical)_62%,var(--vpw-bg-card))] p-5"
      role="alert"
    >
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <span className="grid size-8 shrink-0 place-items-center rounded-full bg-[var(--vpw-red)] text-[var(--vpw-bg-card)]">
            <AlertCircle aria-hidden="true" className="size-4" />
          </span>
          <div>
            <h3 className="text-lg font-semibold text-[var(--vpw-red)]">
              Import failed
            </h3>
            <p className="mt-3 font-semibold text-[var(--vpw-red)]">
              {failedImportRunId
                ? "The import run was recorded, but the parser rejected the supplied evidence."
                : "Parser rejected the supplied evidence before a run could be recorded."}
            </p>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-[var(--vpw-text-secondary)]">
              {importError}
            </p>
          </div>
        </div>
        {failedImportRunId ? (
          <Button asChild variant="outline">
            <Link
              params={{ runId: failedImportRunId }}
              search={{ projectId: selectedProjectId }}
              to="/imports/runs/$runId"
            >
              View recorded run
              <ExternalLink aria-hidden="true" data-icon="inline-end" />
            </Link>
          </Button>
        ) : null}
      </div>
      <div className="border-t border-[color-mix(in_srgb,var(--vpw-red)_24%,var(--vpw-border-default))] pt-5">
        <h4 className="mb-3 text-sm font-semibold text-[var(--vpw-text-primary)]">
          Failure diagnostics preview
        </h4>
        <dl className="grid gap-3 md:grid-cols-2">
          {rows.map((row) => (
            <div
              className="rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-3 py-2.5"
              key={row.label}
            >
              <dt className="vpw-label">{row.label}</dt>
              <dd className="mt-1 min-w-0 font-medium text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]">
                {row.value}
              </dd>
            </div>
          ))}
        </dl>
      </div>
    </div>
  )
}
