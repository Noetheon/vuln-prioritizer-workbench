import { Link } from "@/lib/router"
import { ArrowLeft, ArrowRight, Upload } from "lucide-react"
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
      className="imports-page-shell flex w-full min-w-0 flex-col gap-4"
      onSubmit={handleSubmit}
    >
      <div className="flex justify-end">
        <Button asChild variant="outline">
          <Link search={projectSearch} to="/imports">
            Cancel
          </Link>
        </Button>
      </div>
      <div className="grid min-w-0 gap-6 min-[1240px]:grid-cols-[220px_minmax(0,1fr)_320px] min-[1240px]:items-start">
        <StepNav currentStep={step} onStepChange={setStep} readiness={readiness} />
        <VpwPanel className="flex min-w-0 flex-col gap-5">
          {step === 1 ? <ChooseSourceStep {...props} /> : null}
          {step === 2 ? (
            <UploadFileStep
              {...props}
              format={format}
              parserPreview={parserPreview}
            />
          ) : null}
          {step === 3 ? <AddContextStep {...props} readiness={readiness} /> : null}
          {step === 4 ? (
            <ReviewImportStep
              {...props}
              parserPreview={parserPreview}
              readiness={readiness}
            />
          ) : null}
          {props.importError ? (
            <ImportFailurePanel
              failedImportRunId={props.failedImportRunId}
              importError={props.importError}
            />
          ) : null}
          {props.importLoading ? (
            <VpwStatusBanner title="Importing">
              Preparing upload, uploading evidence, and creating a run.
            </VpwStatusBanner>
          ) : null}
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
        <SummaryRail
          importFailed={importFailed}
          inputTypeLabel={metadataFormat?.label ?? "Not selected"}
          parserPreview={parserPreview}
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
  return (
    <div className="sticky bottom-0 -mx-[var(--vpw-panel-padding)] -mb-[var(--vpw-panel-padding)] flex flex-col gap-3 border-t border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] px-[var(--vpw-panel-padding)] py-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="text-sm text-[var(--vpw-text-muted)]">
        {importLoading
          ? "Creating import run..."
          : continueDisabledReason || readinessCopyForStep(step, readiness)}
      </div>
      <div className="flex flex-wrap gap-2">
        <Button
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
    <div className="sticky bottom-0 -mx-[var(--vpw-panel-padding)] -mb-[var(--vpw-panel-padding)] flex flex-col gap-3 border-t border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] px-[var(--vpw-panel-padding)] py-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="text-sm font-medium text-[var(--vpw-red)]">
        Import failed
      </div>
      <div className="flex flex-wrap gap-2">
        {!failedImportRunId ? (
          <>
            <Button onClick={onBackToFile} type="button" variant="outline">
              Back to file
            </Button>
            <Button onClick={onRetry} type="submit">
              Retry import
            </Button>
          </>
        ) : (
          <>
            <Button onClick={onBackToFile} type="button" variant="outline">
              Back to file
            </Button>
            <Button
              onClick={() => onOpenDiagnostics(failedImportRunId)}
              type="button"
              variant="outline"
            >
              Open diagnostics
            </Button>
            <Button asChild>
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
  importError,
}: {
  failedImportRunId: string
  importError: string
}) {
  return (
    <VpwStatusBanner title="Import failed" tone="critical">
      <div className="grid gap-3">
        <p>
          {failedImportRunId
            ? "The import run was recorded, but the parser rejected the supplied evidence."
            : "Parser rejected the supplied evidence before a run could be recorded."}
        </p>
        <p>{importError}</p>
      </div>
    </VpwStatusBanner>
  )
}
