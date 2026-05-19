import { Link } from "@/lib/router"
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
  type StepId,
  validateAssetContextCsvFile,
  validateVexJsonFile,
} from "./new-import-route-state"
import { ImportFailurePanel } from "./NewImportFailurePanel"
import {
  AddContextStep,
  ChooseSourceStep,
  ReviewImportStep,
  StepNav,
  SummaryRail,
  UploadFileStep,
} from "./NewImportWizardSections"
import { FailureFooter, WizardFooter } from "./NewImportWizardFooter"

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
  const stepContentRef = useRef<HTMLDivElement | null>(null)
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
    const isInitialRender = initialStepRenderRef.current
    initialStepRenderRef.current = false
    window.requestAnimationFrame(() => {
      stepContentRef.current?.scrollTo({ left: 0, top: 0 })
      if (!isInitialRender) {
        stepPanelRef.current?.scrollIntoView({
          block: "start",
          inline: "nearest",
        })
      }
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
            <div
              className="flex min-h-0 min-w-0 flex-1 flex-col gap-5 overflow-y-auto p-5 sm:p-6"
              ref={stepContentRef}
            >
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
