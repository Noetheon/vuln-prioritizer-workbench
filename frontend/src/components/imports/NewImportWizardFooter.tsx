import { Link } from "@/lib/router"
import { ArrowLeft, ArrowRight, Upload } from "lucide-react"
import { Button } from "@/components/ui/button"
import type { buildImportReadinessChecks } from "@/lib/import-format-metadata"
import {
  readinessCopyForStep,
  type StepId,
} from "./new-import-route-state"

export function WizardFooter({
  continueDisabledReason,
  goBack,
  importLoading,
  onContinue,
  onSubmitClick,
  readiness,
  step,
}: {
  continueDisabledReason: string
  goBack: () => void
  importLoading: boolean
  onContinue: () => void
  onSubmitClick: () => void
  readiness: ReturnType<typeof buildImportReadinessChecks>
  step: StepId
}) {
  const readyCopy = readinessCopyForStep(step, readiness)
  const statusDescription = importLoading
    ? "Uploading evidence and creating the import run."
    : continueDisabledReason || actionHintForStep(step, readyCopy)
  return (
    <div
      className="imports-command-bar flex shrink-0 flex-col gap-3 border-t border-[var(--vpw-border-default)] bg-[color-mix(in_srgb,var(--vpw-bg-card)_94%,var(--vpw-bg-panel))] px-5 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-6"
      data-testid="import-wizard-command-bar"
    >
      <div
        aria-live="polite"
        className="min-w-0 text-sm leading-5 text-[var(--vpw-text-muted)]"
      >
        {statusDescription}
      </div>
      <div className="flex w-full flex-col-reverse gap-2 sm:w-auto sm:flex-row sm:justify-end">
        <Button
          className="sm:min-w-24"
          disabled={step === 1 || importLoading}
          onClick={goBack}
          type="button"
          variant="outline"
        >
          <ArrowLeft aria-hidden="true" data-icon="inline-start" />
          Back
        </Button>
        {step < 4 ? (
          <Button
            className="sm:min-w-32"
            disabled={Boolean(continueDisabledReason)}
            onClick={onContinue}
            type="button"
          >
            Continue
            <ArrowRight aria-hidden="true" data-icon="inline-end" />
          </Button>
        ) : (
          <Button
            aria-busy={importLoading}
            className="sm:min-w-36"
            disabled={Boolean(continueDisabledReason)}
            onClick={onSubmitClick}
            type="submit"
          >
            <Upload aria-hidden="true" data-icon="inline-start" />
            {importLoading ? "Importing" : "Start import"}
          </Button>
        )}
      </div>
    </div>
  )
}

function actionHintForStep(step: StepId, readyCopy: string) {
  if (step === 1) return "Continue to upload the evidence file."
  if (step === 2) return "Continue to optional context."
  if (step === 3) return "Continue to review."
  if (readyCopy === "Ready to import") return "Start the import when ready."
  return readyCopy
}

export function FailureFooter({
  failedImportRunId,
  onBackToFile,
  onOpenDiagnostics,
  onRetry,
  selectedProjectId,
}: {
  failedImportRunId: string
  onBackToFile: () => void
  onOpenDiagnostics: (runId: string) => void
  onRetry: () => void
  selectedProjectId: string
}) {
  return (
    <div
      className="imports-command-bar flex shrink-0 flex-col gap-3 border-t border-[var(--vpw-border-default)] bg-[color-mix(in_srgb,var(--vpw-bg-card)_94%,var(--vpw-bg-panel))] px-5 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-6"
      data-testid="import-wizard-command-bar"
    >
      <div
        aria-live="polite"
        className="min-w-0 text-sm leading-5 text-[var(--vpw-text-muted)]"
      >
        <span className="font-medium text-[var(--vpw-red)]">Import failed.</span>{" "}
        {failedImportRunId
          ? "Open diagnostics for the recorded run or go back to fix the file."
          : "Go back to the evidence file or retry the import."}
      </div>
      <div className="flex w-full flex-col-reverse gap-2 sm:w-auto sm:flex-row sm:justify-end">
        {!failedImportRunId ? (
          <>
            <Button
              className="sm:min-w-28"
              onClick={onBackToFile}
              type="button"
              variant="outline"
            >
              Back to file
            </Button>
            <Button className="sm:min-w-32" onClick={onRetry} type="submit">
              Retry import
            </Button>
          </>
        ) : (
          <>
            <Button
              className="sm:min-w-28"
              onClick={onBackToFile}
              type="button"
              variant="outline"
            >
              Back to file
            </Button>
            <Button
              className="sm:min-w-36"
              onClick={() => onOpenDiagnostics(failedImportRunId)}
              type="button"
              variant="outline"
            >
              Open diagnostics
            </Button>
            <Button asChild className="sm:min-w-36">
              <Link
                params={{ runId: failedImportRunId }}
                search={{ projectId: selectedProjectId }}
                to="/imports/runs/$runId"
              >
                Open run detail
              </Link>
            </Button>
          </>
        )}
      </div>
    </div>
  )
}
