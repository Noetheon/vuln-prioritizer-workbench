import { Link } from "@/lib/router"
import {
  AlertCircle,
  ArrowLeft,
  ArrowRight,
  ExternalLink,
  Upload,
} from "lucide-react"
import { type FormEventHandler, useEffect, useMemo, useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import { VpwPanel, VpwStatusBanner } from "@/components/vpw"
import {
  buildImportReadinessChecks,
  buildParserPreview,
  getImportFormat,
  initialParserPreview,
  readinessBlocksImport,
  type ParserPreview,
} from "@/lib/import-format-metadata"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  selectedFormat,
  type ImportsWorkbenchProps,
} from "./imports-workbench-model"
import {
  disabledReasonForStep,
  fileKey,
  optionalContextReadiness,
  type OptionalContextValidationState,
  readinessCopyForStep,
  type StepId,
  validateAssetContextCsvFile,
  validateVexJsonFile,
} from "./new-import-route-state"
import {
  AddContextStep,
  ChooseSourceStep,
  ReviewImportStep,
  StepNav,
  SummaryRail,
  UploadFileStep,
} from "./NewImportWizardSections"

type NewImportRouteProps = ImportsWorkbenchProps & {
  onOpenDiagnostics: (runId: string) => void
}

type OptionalContextValidationMap = {
  assetContext: OptionalContextValidationState | null
  vex: OptionalContextValidationState | null
}

export function NewImportRoute(props: NewImportRouteProps) {
  const [step, setStep] = useState<StepId>(1)
  const [parserPreview, setParserPreview] =
    useState<ParserPreview>(initialParserPreview)
  const [optionalContextValidation, setOptionalContextValidation] =
    useState<OptionalContextValidationMap>({ assetContext: null, vex: null })
  const submitRequestedRef = useRef(false)
  const stepPanelRef = useRef<HTMLDivElement | null>(null)
  const initialStepRenderRef = useRef(true)
  const format = selectedFormat(props.supportedFormats, props.importWizard.inputType)
  const metadataFormat = getImportFormat(props.importWizard.inputType)
  const projectSearch = selectedProjectRouteSearch(props.selectedProjectId)
  const importFailed = Boolean(props.importError)
  const readiness = useMemo(() => {
    const baseChecks = buildImportReadinessChecks({
      evidenceFile: props.importWizard.file,
      inputType: props.importWizard.inputType,
      parserPreview,
      projectId: props.selectedProjectId,
      providerAvailable: props.providerStatus?.status === "ok",
    })
    const optionalChecks = optionalContextReadiness({
      attackMappingFile: props.importWizard.attackMappingFile,
      attackSource: props.importWizard.attackSource,
      assetContextFile: props.importWizard.assetContextFile,
      assetContextValidation: optionalContextValidation.assetContext,
      vexFile: props.importWizard.vexFile,
      vexValidation: optionalContextValidation.vex,
    })
    return baseChecks.map((check) => optionalChecks[check.id] ?? check)
  }, [
    optionalContextValidation.assetContext,
    optionalContextValidation.vex,
    parserPreview,
    props.importWizard.assetContextFile,
    props.importWizard.attackMappingFile,
    props.importWizard.attackSource,
    props.importWizard.file,
    props.importWizard.inputType,
    props.importWizard.vexFile,
    props.providerStatus?.status,
    props.selectedProjectId,
  ])
  const canStartImport = !readinessBlocksImport(readiness)
  const continueDisabledReason = disabledReasonForStep({
    canStartImport,
    importLoading: props.importLoading,
    parserPreview,
    selectedProjectId: props.selectedProjectId,
    step,
    inputType: props.importWizard.inputType,
    evidenceFile: props.importWizard.file,
  })

  useEffect(() => {
    let cancelled = false
    setParserPreview(
      props.importWizard.file && props.importWizard.inputType
        ? { ...initialParserPreview(), state: "checking" }
        : initialParserPreview(),
    )
    void buildParserPreview(
      props.importWizard.file,
      props.importWizard.inputType,
    ).then((preview) => {
      if (!cancelled) setParserPreview(preview)
    })
    return () => {
      cancelled = true
    }
  }, [props.importWizard.file, props.importWizard.inputType])

  useEffect(() => {
    if (step < 1) return
    if (initialStepRenderRef.current) {
      initialStepRenderRef.current = false
      return
    }
    window.requestAnimationFrame(() => {
      stepPanelRef.current?.scrollIntoView({
        block: "start",
        inline: "nearest",
      })
    })
  }, [step])

  useEffect(() => {
    const file = props.importWizard.assetContextFile
    if (!file) {
      setOptionalContextValidation((state) => ({ ...state, assetContext: null }))
      return
    }
    const currentFileKey = fileKey(file)
    let cancelled = false
    setOptionalContextValidation((state) => ({
      ...state,
      assetContext: {
        fileKey: currentFileKey,
        message: "Checking asset context CSV.",
        status: "checking",
      },
    }))
    void validateAssetContextCsvFile(file).then((result) => {
      if (!cancelled) {
        setOptionalContextValidation((state) => ({
          ...state,
          assetContext: result,
        }))
      }
    })
    return () => {
      cancelled = true
    }
  }, [props.importWizard.assetContextFile])

  useEffect(() => {
    const file = props.importWizard.vexFile
    if (!file) {
      setOptionalContextValidation((state) => ({ ...state, vex: null }))
      return
    }
    const currentFileKey = fileKey(file)
    let cancelled = false
    setOptionalContextValidation((state) => ({
      ...state,
      vex: {
        fileKey: currentFileKey,
        message: "Checking VEX overlay JSON.",
        status: "checking",
      },
    }))
    void validateVexJsonFile(file).then((result) => {
      if (!cancelled) {
        setOptionalContextValidation((state) => ({
          ...state,
          vex: result,
        }))
      }
    })
    return () => {
      cancelled = true
    }
  }, [props.importWizard.vexFile])

  function continueToNextStep() {
    if (step < 4 && !continueDisabledReason) {
      setStep((current) => Math.min(4, current + 1) as StepId)
    }
  }

  function goBack() {
    setStep((current) => Math.max(1, current - 1) as StepId)
  }

  const handleSubmit: FormEventHandler<HTMLFormElement> = (event) => {
    if (!submitRequestedRef.current) {
      event.preventDefault()
      return
    }
    submitRequestedRef.current = false
    props.onSubmit(event)
  }

  return (
    <form
      className="imports-page-shell flex w-full min-w-0 flex-col gap-6"
      onSubmit={handleSubmit}
    >
      <div className="flex justify-end">
        <Button asChild variant="outline">
          <Link search={projectSearch} to="/imports">
            Cancel
          </Link>
        </Button>
      </div>
      <div className="imports-wizard-layout grid min-w-0 gap-6">
        <StepNav currentStep={step} onStepChange={setStep} readiness={readiness} />
        <div className="min-w-0 lg:h-full" ref={stepPanelRef}>
          <VpwPanel className="flex min-w-0 flex-col overflow-hidden p-0 lg:h-full lg:max-h-[var(--imports-wizard-panel-height)]">
            <div className="flex min-h-0 min-w-0 flex-1 flex-col gap-5 overflow-y-auto p-5 sm:p-6">
              {step === 1 ? <ChooseSourceStep {...props} /> : null}
              {step === 2 ? (
                <UploadFileStep
                  {...props}
                  format={format}
                  parserPreview={parserPreview}
                />
              ) : null}
              {step === 3 ? (
                <AddContextStep {...props} readiness={readiness} />
              ) : null}
              {step === 4 && !importFailed ? (
                <ReviewImportStep
                  {...props}
                  parserPreview={parserPreview}
                  readiness={readiness}
                />
              ) : null}
              {step === 4 && importFailed ? (
                <ImportFailurePanel
                  failedImportRunId={props.failedImportRunId}
                  importWizard={props.importWizard}
                  importError={props.importError}
                  selectedProjectId={props.selectedProjectId}
                />
              ) : null}
              {props.importLoading ? (
                <VpwStatusBanner title="Importing">
                  Preparing upload, uploading evidence, and creating a run.
                </VpwStatusBanner>
              ) : null}
            </div>
            {importFailed ? (
              <FailureFooter
                failedImportRunId={props.failedImportRunId}
                onBackToFile={() => setStep(2)}
                onOpenDiagnostics={props.onOpenDiagnostics}
                onRetry={() => {
                  submitRequestedRef.current = true
                }}
                selectedProjectId={props.selectedProjectId}
              />
            ) : (
              <WizardFooter
                continueDisabledReason={continueDisabledReason}
                goBack={goBack}
                importLoading={props.importLoading}
                onContinue={continueToNextStep}
                onSubmitClick={() => {
                  submitRequestedRef.current = true
                }}
                readiness={readiness}
                step={step}
              />
            )}
          </VpwPanel>
        </div>
        <SummaryRail
          importFailed={importFailed}
          inputTypeLabel={metadataFormat?.label ?? "Not selected"}
          props={props}
          readiness={readiness}
          step={step}
        />
      </div>
    </form>
  )
}

function WizardFooter({
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

function FailureFooter({
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

function ImportFailurePanel({
  failedImportRunId,
  importWizard,
  importError,
  selectedProjectId,
}: {
  failedImportRunId: string
  importWizard: NewImportRouteProps["importWizard"]
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
