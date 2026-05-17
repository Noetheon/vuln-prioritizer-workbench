import { Link } from "@/lib/router"
import {
  ArrowLeft,
  ArrowRight,
  Check,
  Circle,
  Info,
  Upload,
  X,
} from "lucide-react"
import { type FormEventHandler, useEffect, useMemo, useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  MetaTag,
  VpwBadge,
  VpwKeyValueList,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwSelectionCard,
  VpwStatusBanner,
} from "@/components/vpw"
import {
  buildImportReadinessChecks,
  buildParserPreview,
  FORMAT_CATEGORY_LABELS,
  getImportFormat,
  initialParserPreview,
  readinessBlocksImport,
  SUPPORTED_IMPORT_FORMATS,
  type ImportReadinessCheck,
  type ParserPreview,
  type SupportedFormatCategory,
} from "@/lib/import-format-metadata"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import { FileUploadField } from "./ImportsWorkbenchFileUploadField"
import { ProviderAttackOptions } from "./ImportsWorkbenchProviderOptions"
import {
  fileSizeLabel,
  formatExpectedFields,
  hasOptionalContext,
  optionalContextLabels,
  selectedFormat,
  type ImportsWorkbenchProps,
} from "./imports-workbench-model"

type StepId = 1 | 2 | 3 | 4

const stepLabels: Array<{ id: StepId; label: string; description: string }> = [
  { id: 1, label: "Choose source", description: "Project and input type" },
  { id: 2, label: "Upload file", description: "Main evidence file" },
  { id: 3, label: "Add context", description: "Optional local context" },
  { id: 4, label: "Review import", description: "Readiness and submit" },
]

const categoryOrder: SupportedFormatCategory[] = [
  "simple",
  "scanner",
  "sbom",
  "network",
]

export function NewImportRoute(props: ImportsWorkbenchProps) {
  const [step, setStep] = useState<StepId>(1)
  const [parserPreview, setParserPreview] =
    useState<ParserPreview>(initialParserPreview)
  const submitRequestedRef = useRef(false)
  const format = selectedFormat(props.supportedFormats, props.importWizard.inputType)
  const metadataFormat = getImportFormat(props.importWizard.inputType)
  const optionalLabels = optionalContextLabels(props.importWizard)
  const projectSearch = selectedProjectRouteSearch(props.selectedProjectId)
  const readiness = useMemo(
    () =>
      buildImportReadinessChecks({
        evidenceFile: props.importWizard.file,
        inputType: props.importWizard.inputType,
        parserPreview,
        projectId: props.selectedProjectId,
        providerAvailable: props.providerStatus?.status === "ok",
      }),
    [
      parserPreview,
      props.importWizard.file,
      props.importWizard.inputType,
      props.providerStatus?.status,
      props.selectedProjectId,
    ],
  )
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
    void buildParserPreview(props.importWizard.file, props.importWizard.inputType).then(
      (preview) => {
        if (!cancelled) setParserPreview(preview)
      },
    )
    return () => {
      cancelled = true
    }
  }, [props.importWizard.file, props.importWizard.inputType])

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
      className="imports-page-shell mx-auto flex w-full max-w-[1480px] flex-col gap-4"
      onSubmit={handleSubmit}
    >
      <VpwSection>
        <VpwSectionHeader
          actions={
            <Button asChild variant="outline">
              <Link search={projectSearch} to="/imports">
                Cancel
              </Link>
            </Button>
          }
          description="Upload supplied evidence and create findings for triage."
          title="New import"
        />
      </VpwSection>
      <div className="grid gap-4 lg:grid-cols-[260px_minmax(0,760px)] lg:justify-center min-[1600px]:grid-cols-[260px_minmax(640px,760px)_340px] min-[1600px]:justify-start">
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
          {step === 3 ? <AddContextStep {...props} /> : null}
          {step === 4 ? (
            <ReviewImportStep
              {...props}
              parserPreview={parserPreview}
              readiness={readiness}
            />
          ) : null}
          {props.importError ? (
            <VpwStatusBanner title="Import failed before run creation" tone="critical">
              {props.importError}
            </VpwStatusBanner>
          ) : null}
          {props.importLoading ? (
            <VpwStatusBanner title="Importing">
              Preparing upload, uploading evidence, and creating a run.
            </VpwStatusBanner>
          ) : null}
          <div className="sticky bottom-0 -mx-[var(--vpw-panel-padding)] -mb-[var(--vpw-panel-padding)] flex flex-col gap-3 border-t border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] px-[var(--vpw-panel-padding)] py-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="text-sm text-[var(--vpw-text-muted)]">
              {continueDisabledReason || "Can continue"}
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                disabled={step === 1 || props.importLoading}
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
                  onClick={continueToNextStep}
                  type="button"
                >
                  Continue
                  <ArrowRight aria-hidden="true" data-icon="inline-end" />
                </Button>
              ) : (
                <Button
                  aria-busy={props.importLoading}
                  disabled={Boolean(continueDisabledReason)}
                  onClick={() => {
                    submitRequestedRef.current = true
                  }}
                  type="submit"
                >
                  <Upload aria-hidden="true" data-icon="inline-start" />
                  {props.importLoading ? "Importing" : "Start import"}
                </Button>
              )}
            </div>
          </div>
        </VpwPanel>
        <SummaryRail
          inputTypeLabel={metadataFormat?.label ?? "Not selected"}
          optionalLabels={optionalLabels}
          parserPreview={parserPreview}
          props={props}
          readiness={readiness}
        />
      </div>
    </form>
  )
}

function StepNav({
  currentStep,
  onStepChange,
  readiness,
}: {
  currentStep: StepId
  onStepChange: (step: StepId) => void
  readiness: readonly ImportReadinessCheck[]
}) {
  const canReachStep2 =
    checkPassed(readiness, "project") && checkPassed(readiness, "input-type")
  const parserReady =
    checkPassed(readiness, "parser-preview") ||
    checkHasStatus(readiness, "parser-preview", "warning")
  const canReachStep3 =
    canReachStep2 &&
    checkPassed(readiness, "evidence-file") &&
    checkPassed(readiness, "file-type") &&
    parserReady
  const canReachStep4 = canReachStep3

  return (
    <VpwPanel className="flex flex-col gap-2">
      {stepLabels.map((item) => {
        const reachable =
          item.id === 1 ||
          (item.id === 2 && canReachStep2) ||
          (item.id === 3 && canReachStep3) ||
          (item.id === 4 && canReachStep4)
        const completed = item.id < currentStep
        const active = item.id === currentStep
        const Icon = completed ? Check : active ? Info : Circle
        const blockedReason = reachable
          ? ""
          : blockedStepReason(item.id, canReachStep2, canReachStep3)
        return (
          <Button
            aria-current={active ? "step" : undefined}
            className={[
              "flex min-h-14 w-full items-start gap-3 rounded-[var(--vpw-radius-md)] border px-3 py-2 text-left text-sm transition-colors",
              active
                ? "border-[var(--vpw-text-primary)] bg-[var(--vpw-bg-card)] text-[var(--vpw-text-primary)]"
                : "border-[var(--vpw-border-default)] text-[var(--vpw-text-secondary)]",
              reachable ? "hover:bg-[var(--vpw-bg-panel)]" : "cursor-not-allowed opacity-70",
            ].join(" ")}
            disabled={!reachable}
            key={item.id}
            onClick={() => reachable && onStepChange(item.id)}
            type="button"
            variant="outline"
          >
            <Icon aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
            <span className="min-w-0">
              <span className="block font-medium">{item.label}</span>
              <span className="mt-0.5 block text-xs text-[var(--vpw-text-muted)]">
                {blockedReason || item.description}
              </span>
            </span>
          </Button>
        )
      })}
    </VpwPanel>
  )
}

function ChooseSourceStep({
  importWizard,
  onInputTypeChange,
  onProjectChange,
  projectListLoading,
  projects,
  selectedProjectId,
}: ImportsWorkbenchProps) {
  const projectDisabledReason = projectListLoading
    ? "Projects are loading."
    : projects.length === 0
      ? "No projects available."
      : ""
  return (
    <section className="flex flex-col gap-5">
      <VpwSectionHeader
        description="Select the project and evidence format you want to import."
        title="Choose source"
      />
      <div className="grid gap-3">
        <label className="vpw-label" htmlFor="import-project">
          Project
        </label>
        <Select
          disabled={projectListLoading || projects.length === 0}
          name="importProject"
          onValueChange={onProjectChange}
          value={selectedProjectId}
        >
          <SelectTrigger aria-label="Import project" id="import-project">
            <SelectValue placeholder="Select project" />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              {projects.map((project) => (
                <SelectItem key={project.id} value={project.id}>
                  {project.name}
                </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
        {projectDisabledReason ? (
          <p className="text-sm text-[var(--vpw-text-muted)]">
            {projectDisabledReason}
          </p>
        ) : null}
      </div>
      <div className="grid gap-5">
        {categoryOrder.map((category) => (
          <div className="grid gap-3" key={category}>
            <h3 className="text-sm font-semibold text-[var(--vpw-text-primary)]">
              {FORMAT_CATEGORY_LABELS[category]}
            </h3>
            <div className="grid gap-3 md:grid-cols-2">
              {SUPPORTED_IMPORT_FORMATS.filter((format) => format.category === category).map(
                (format) => (
                  <VpwSelectionCard
                    checked={importWizard.inputType === format.inputType}
                    key={format.inputType}
                    meta={format.extensions.join(", ")}
                    onClick={() => onInputTypeChange(format.inputType)}
                    title={format.label}
                  >
                    {format.shortDescription}
                  </VpwSelectionCard>
                ),
              )}
            </div>
          </div>
        ))}
      </div>
      {importWizard.inputType ? (
        <div className="rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-panel)] p-4">
          <VpwKeyValueList
            columns={2}
            items={[
              {
                label: "Input type",
                value: getImportFormat(importWizard.inputType)?.label,
              },
              {
                label: "Expected shape",
                value: getImportFormat(importWizard.inputType)?.expectedShape,
              },
              {
                label: "Accepted extensions",
                value: getImportFormat(importWizard.inputType)?.extensions.join(", "),
              },
              {
                label: "Minimum fields",
                value: formatExpectedFields(importWizard.inputType),
              },
            ]}
          />
        </div>
      ) : null}
    </section>
  )
}

function UploadFileStep({
  format,
  importWizard,
  onFileChange,
  parserPreview,
}: Pick<ImportsWorkbenchProps, "importWizard" | "onFileChange"> & {
  format: ImportsWorkbenchProps["supportedFormats"][number] | undefined
  parserPreview: ParserPreview
}) {
  return (
    <section className="flex flex-col gap-5">
      <VpwSectionHeader
        description="Attach the main evidence file for the selected input type."
        title="Upload file"
      />
      <div className="rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-panel)] p-4">
        <p className="font-medium text-[var(--vpw-text-primary)]">
          {format?.label ?? "Input type not selected"}
        </p>
        <p className="mt-1 text-sm text-[var(--vpw-text-secondary)]">
          {format?.detail ?? "Choose an input type before uploading evidence."}
        </p>
      </div>
      <FileUploadField
        accept={format?.accept}
        description={`Accepted file types: ${format?.accept ?? "select input type first"}`}
        file={importWizard.file}
        id="import-file"
        label="Evidence file"
        name="importFile"
        onFileChange={onFileChange}
        required
      />
      <ParserPreviewPanel parserPreview={parserPreview} />
    </section>
  )
}

function AddContextStep(props: ImportsWorkbenchProps) {
  return (
    <section className="flex flex-col gap-5">
      <VpwSectionHeader
        description="Optional context can improve prioritization and explanations. You can skip this step."
        title="Add context"
      />
      <div className="grid gap-4 md:grid-cols-2">
        <FileUploadField
          accept=".csv,text/csv"
          description="Optional CSV with owner, service, environment, exposure, and criticality context."
          file={props.importWizard.assetContextFile}
          id="asset-context-file"
          label="Asset context CSV"
          name="assetContextFile"
          onFileChange={props.onAssetContextFileChange}
        />
        <FileUploadField
          accept=".json,application/json"
          description="Optional OpenVEX or CycloneDX VEX sidecar."
          file={props.importWizard.vexFile}
          id="vex-file"
          label="VEX overlay"
          name="vexFile"
          onFileChange={props.onVexFileChange}
        />
      </div>
      <VpwStatusBanner title="ATT&CK/TTP context">
        Adds reviewed defensive ATT&CK mappings where available. Unmapped CVEs remain unmapped, and this context does not override base priority.
      </VpwStatusBanner>
      <details className="rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)]">
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-[var(--vpw-text-primary)]">
          Advanced provider data and reviewed ATT&CK context
        </summary>
        <div className="border-t border-[var(--vpw-border-default)] p-4">
          <ProviderAttackOptions
            importWizard={props.importWizard}
            onAttackMappingFileChange={props.onAttackMappingFileChange}
            onAttackSourceChange={props.onAttackSourceChange}
            onAttackTechniqueMetadataFileChange={
              props.onAttackTechniqueMetadataFileChange
            }
            onLockedProviderDataChange={props.onLockedProviderDataChange}
            onProviderSnapshotFileChange={props.onProviderSnapshotFileChange}
            onUseDemoProviderSnapshot={props.onUseDemoProviderSnapshot}
          />
        </div>
      </details>
    </section>
  )
}

function ReviewImportStep({
  importWizard,
  parserPreview,
  readiness,
  selectedProject,
}: ImportsWorkbenchProps & {
  parserPreview: ParserPreview
  readiness: readonly ImportReadinessCheck[]
}) {
  const format = getImportFormat(importWizard.inputType)
  return (
    <section className="flex flex-col gap-5">
      <VpwSectionHeader
        description="Review settings and validate readiness before creating a run."
        title="Review import"
      />
      <ReadinessList readiness={readiness} />
      <div className="rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-panel)] p-4">
        <VpwSectionHeader
          description={
            parserPreview.candidateRows === undefined
              ? "Full parser results will be available after import."
              : `${parserPreview.candidateRows} candidate row(s) detected by shallow preview.`
          }
          title="Preview summary"
        />
      </div>
      <VpwKeyValueList
        columns={2}
        items={[
          { label: "Project", value: selectedProject?.name ?? "Required" },
          { label: "Input type", value: format?.label ?? "Required" },
          {
            label: "Evidence file",
            value: importWizard.file
              ? `${importWizard.file.name} - ${fileSizeLabel(importWizard.file)}`
              : "Required",
          },
          {
            label: "Provider data",
            value: importWizard.providerSnapshotFile
              ? importWizard.providerSnapshotFile
              : "Current provider data",
          },
          {
            label: "Asset context",
            value: importWizard.assetContextFile?.name ?? "Not selected",
          },
          {
            label: "VEX",
            value: importWizard.vexFile?.name ?? "Not selected",
          },
          {
            label: "ATT&CK context",
            value:
              importWizard.attackSource && importWizard.attackSource !== "none"
                ? "Reviewed defensive context configured"
                : "Not selected",
          },
          {
            label: "Deterministic replay",
            value: importWizard.lockedProviderData ? "Yes" : "No",
          },
        ]}
      />
    </section>
  )
}

function ParserPreviewPanel({ parserPreview }: { parserPreview: ParserPreview }) {
  if (parserPreview.state === "not-started") {
    return (
      <VpwStatusBanner title="Evidence file is required" tone="warning">
        Choose a file before continuing.
      </VpwStatusBanner>
    )
  }
  if (parserPreview.state === "checking") {
    return <VpwStatusBanner title="Checking file">Preparing shallow parser preview.</VpwStatusBanner>
  }
  if (parserPreview.state === "error") {
    return (
      <VpwStatusBanner title="File cannot be prepared for import" tone="critical">
        {parserPreview.errors.join(" ")}
      </VpwStatusBanner>
    )
  }
  return (
    <VpwStatusBanner
      title={parserPreview.warnings.length > 0 ? "Parser preview warning" : "File check passed"}
      tone={parserPreview.warnings.length > 0 ? "warning" : "success"}
    >
      {parserPreview.candidateRows === undefined
        ? "File selected. Full parser validation will run when the import starts."
        : `${parserPreview.candidateRows} candidate row(s) detected.`}
      {parserPreview.warnings.length > 0 ? ` ${parserPreview.warnings.join(" ")}` : ""}
    </VpwStatusBanner>
  )
}

function ReadinessList({
  readiness,
}: {
  readiness: readonly ImportReadinessCheck[]
}) {
  return (
    <div className="grid gap-2">
      {readiness.map((check) => (
        <div
          className="flex items-start gap-3 rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-3"
          key={check.id}
        >
          <ReadinessIcon status={check.status} />
          <div className="min-w-0">
            <p className="font-medium text-[var(--vpw-text-primary)]">
              {check.label}
            </p>
            {check.message ? (
              <p className="mt-1 text-sm text-[var(--vpw-text-secondary)]">
                {check.message}
              </p>
            ) : null}
          </div>
        </div>
      ))}
    </div>
  )
}

function ReadinessIcon({ status }: { status: ImportReadinessCheck["status"] }) {
  const className =
    status === "passed"
      ? "text-[var(--vpw-green)]"
      : status === "missing" || status === "error"
        ? "text-[var(--vpw-red)]"
        : status === "warning"
          ? "text-[var(--vpw-amber)]"
          : "text-[var(--vpw-text-muted)]"
  const Icon = status === "passed" ? Check : status === "missing" || status === "error" ? X : Circle
  return <Icon aria-hidden="true" className={`mt-0.5 size-4 shrink-0 ${className}`} />
}

function SummaryRail({
  inputTypeLabel,
  optionalLabels,
  parserPreview,
  props,
  readiness,
}: {
  inputTypeLabel: string
  optionalLabels: string[]
  parserPreview: ParserPreview
  props: ImportsWorkbenchProps
  readiness: readonly ImportReadinessCheck[]
}) {
  const blocking = readiness.find(
    (check) => check.status === "missing" || check.status === "error",
  )
  return (
    <VpwPanel
      className="flex flex-col gap-4 lg:col-start-2 min-[1600px]:col-start-auto"
      data-testid="import-summary-rail"
    >
      <VpwSectionHeader title="Import summary" />
      <VpwKeyValueList
        items={[
          {
            label: "Project",
            value: props.selectedProject?.name ?? "Required",
          },
          {
            label: "Input type",
            value: inputTypeLabel,
          },
          {
            label: "Evidence file",
            value: props.importWizard.file?.name ?? "Next: upload evidence file",
          },
          {
            label: "Optional context",
            value: optionalLabels.length > 0 ? optionalLabels.join(", ") : "None",
          },
          {
            label: "Provider data",
            value: props.importWizard.providerSnapshotFile
              ? props.importWizard.providerSnapshotFile
              : "Current provider data",
          },
          {
            label: "Readiness",
            value: blocking?.message ?? "Ready to import",
          },
        ]}
      />
      <div className="flex flex-wrap gap-2">
        {hasOptionalContext(props.importWizard)
          ? optionalLabels.map((label) => <MetaTag key={label} label={label} />)
          : null}
        {parserPreview.state === "passed" ? (
          <VpwBadge tone="success">File check passed</VpwBadge>
        ) : null}
      </div>
    </VpwPanel>
  )
}

function disabledReasonForStep({
  canStartImport,
  evidenceFile,
  importLoading,
  inputType,
  parserPreview,
  selectedProjectId,
  step,
}: {
  canStartImport: boolean
  evidenceFile: File | null
  importLoading: boolean
  inputType: string
  parserPreview: ParserPreview
  selectedProjectId: string
  step: StepId
}) {
  if (importLoading) return "Import is running."
  if (step === 1) {
    if (!selectedProjectId) return "Select a project to continue."
    if (!inputType) return "Select an input type to continue."
    return ""
  }
  if (step === 2) {
    if (!evidenceFile) return "Continue is unavailable until an evidence file is selected."
    if (parserPreview.state === "not-started") return "File check has not started yet."
    if (parserPreview.state === "checking") return "File check is still running."
    if (parserPreview.state === "error") return parserPreview.errors[0] ?? "Fix the file before continuing."
    return ""
  }
  if (step === 3) return ""
  if (!canStartImport) return "Fix blocking readiness items before starting import."
  return ""
}

function checkPassed(
  readiness: readonly ImportReadinessCheck[],
  id: ImportReadinessCheck["id"],
) {
  return readiness.find((check) => check.id === id)?.status === "passed"
}

function checkHasStatus(
  readiness: readonly ImportReadinessCheck[],
  id: ImportReadinessCheck["id"],
  status: ImportReadinessCheck["status"],
) {
  return readiness.find((check) => check.id === id)?.status === status
}

function blockedStepReason(
  stepId: StepId,
  canReachStep2: boolean,
  canReachStep3: boolean,
) {
  if (stepId === 2 && !canReachStep2) return "Select project and input type first."
  if ((stepId === 3 || stepId === 4) && !canReachStep3) {
    return "Upload a valid evidence file first."
  }
  return ""
}
