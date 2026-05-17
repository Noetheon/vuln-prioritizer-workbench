import { Link } from "@/lib/router"
import { Check, Circle, Info, X } from "lucide-react"
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
  VpwSectionHeader,
  VpwSelectionCard,
  VpwStatusBanner,
} from "@/components/vpw"
import {
  FORMAT_CATEGORY_LABELS,
  getImportFormat,
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
  type ImportsWorkbenchProps,
} from "./imports-workbench-model"
import {
  blockedStepReason,
  checkHasStatus,
  checkPassed,
  readinessCopyForStep,
  readinessToneForStep,
  type StepId,
  stepLabels,
} from "./new-import-route-state"

const categoryOrder: SupportedFormatCategory[] = [
  "simple",
  "scanner",
  "sbom",
  "network",
]

export function StepNav({
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
    <VpwPanel className="flex flex-col gap-1.5 p-3">
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
              "flex h-auto min-h-12 w-full items-start gap-2.5 whitespace-normal rounded-[var(--vpw-radius-md)] border px-2.5 py-2 text-left text-sm transition-colors",
              active
                ? "border-[var(--vpw-text-primary)] bg-[var(--vpw-bg-card)] text-[var(--vpw-text-primary)]"
                : "border-[var(--vpw-border-default)] text-[var(--vpw-text-secondary)]",
              reachable
                ? "hover:bg-[var(--vpw-bg-panel)]"
                : "cursor-not-allowed opacity-70",
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
              {active || blockedReason ? (
                <span className="mt-0.5 block text-xs text-[var(--vpw-text-muted)]">
                  {blockedReason || item.description}
                </span>
              ) : null}
            </span>
          </Button>
        )
      })}
    </VpwPanel>
  )
}

export function ChooseSourceStep({
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
        actions={
          <Button asChild size="sm" variant="outline">
            <Link
              search={selectedProjectRouteSearch(selectedProjectId)}
              to="/imports/formats"
            >
              Supported formats
            </Link>
          </Button>
        }
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
              {SUPPORTED_IMPORT_FORMATS.filter(
                (format) => format.category === category,
              ).map((format) => (
                <VpwSelectionCard
                  checked={importWizard.inputType === format.inputType}
                  key={format.inputType}
                  meta={format.extensions.join(", ")}
                  onClick={() => onInputTypeChange(format.inputType)}
                  title={format.label}
                >
                  {format.shortDescription}
                </VpwSelectionCard>
              ))}
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

export function UploadFileStep({
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
        description={`Accepted: ${format?.accept?.replaceAll(",", " · ") ?? "select input type first"}`}
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

export function AddContextStep(
  props: ImportsWorkbenchProps & {
    readiness: readonly ImportReadinessCheck[]
  },
) {
  const assetContextCheck = props.readiness.find(
    (check) => check.id === "asset-context",
  )
  const vexCheck = props.readiness.find((check) => check.id === "vex")
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
      {assetContextCheck?.status === "error" ? (
        <VpwStatusBanner title="Asset context file needs attention" tone="critical">
          {assetContextCheck.message}
        </VpwStatusBanner>
      ) : null}
      {vexCheck?.status === "error" ? (
        <VpwStatusBanner title="VEX overlay needs attention" tone="critical">
          {vexCheck.message}
        </VpwStatusBanner>
      ) : null}
      <VpwStatusBanner title="ATT&CK/TTP context">
        Adds reviewed defensive ATT&CK mappings where available. Unmapped CVEs remain
        unmapped, and this context does not override base priority.
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

export function ReviewImportStep({
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
    <section className="flex flex-col gap-4">
      <VpwSectionHeader
        description="Review settings and validate readiness before creating a run."
        title="Review import"
      />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(260px,0.9fr)]">
        <div className="rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] p-4">
          <h3 className="text-base font-semibold text-[var(--vpw-text-primary)]">
            Readiness
          </h3>
          <ReadinessList readiness={readiness} />
        </div>
        <div className="rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] p-4">
          <h3 className="text-base font-semibold text-[var(--vpw-text-primary)]">
            Preview
          </h3>
          <PreviewSummary parserPreview={parserPreview} />
        </div>
      </div>
      <div className="grid gap-3">
        <h3 className="text-base font-semibold text-[var(--vpw-text-primary)]">
          Import settings
        </h3>
        <VpwKeyValueList
          columns={2}
          density="compact"
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
      </div>
    </section>
  )
}

export function SummaryRail({
  inputTypeLabel,
  optionalLabels,
  parserPreview,
  props,
  readiness,
  step,
}: {
  inputTypeLabel: string
  optionalLabels: string[]
  parserPreview: ParserPreview
  props: ImportsWorkbenchProps
  readiness: readonly ImportReadinessCheck[]
  step: StepId
}) {
  return (
    <VpwPanel
      className="import-summary-rail flex flex-col gap-4 min-[1240px]:sticky min-[1240px]:top-6"
      data-testid="import-summary-rail"
    >
      <VpwSectionHeader title="Import summary" />
      <VpwKeyValueList
        density="compact"
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
            value: readinessCopyForStep(step, readiness, props.importLoading),
            tone: readinessToneForStep(step, readiness),
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

function ParserPreviewPanel({ parserPreview }: { parserPreview: ParserPreview }) {
  if (parserPreview.state === "not-started") {
    return (
      <VpwStatusBanner title="Evidence file is required" tone="warning">
        Choose a file before continuing.
      </VpwStatusBanner>
    )
  }
  if (parserPreview.state === "checking") {
    return (
      <VpwStatusBanner title="Checking file">
        Preparing shallow parser preview.
      </VpwStatusBanner>
    )
  }
  if (parserPreview.state === "error") {
    return (
      <VpwStatusBanner title="File cannot be prepared for import" tone="critical">
        {parserPreview.errors.join(" ")}
      </VpwStatusBanner>
    )
  }
  return (
    <div className="rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="font-semibold text-[var(--vpw-text-primary)]">
            {parserPreview.warnings.length > 0
              ? "Parser preview warning"
              : "Shallow parser preview passed"}
          </p>
          <p className="mt-1 text-sm text-[var(--vpw-text-secondary)]">
            Full parser results will be available after import.
          </p>
        </div>
        <VpwBadge tone={parserPreview.warnings.length > 0 ? "warning" : "success"}>
          {parserPreview.warnings.length > 0 ? "Warning" : "Passed"}
        </VpwBadge>
      </div>
      <VpwKeyValueList
        className="mt-4"
        columns={2}
        density="compact"
        items={[
          {
            label: "File type",
            value: parserPreview.detectedInputType
              ? getImportFormat(parserPreview.detectedInputType)?.label
              : "Matches selected format",
          },
          {
            label: "Required fields",
            value:
              parserPreview.requiredFieldsFound &&
              parserPreview.requiredFieldsFound.length > 0
                ? parserPreview.requiredFieldsFound.join(", ")
                : "Checked by full parser after import",
          },
          {
            label: "Candidate findings",
            value: parserPreview.candidateRows ?? "Available after import",
          },
          {
            label: "Ignored lines",
            value: parserPreview.ignoredRows ?? "Available after import",
          },
          {
            label: "Parser warnings",
            value: parserPreview.warnings.length,
            tone: parserPreview.warnings.length > 0 ? "warning" : undefined,
          },
          {
            label: "Parser errors",
            value: parserPreview.errors.length,
            tone: parserPreview.errors.length > 0 ? "critical" : undefined,
          },
        ]}
      />
      {parserPreview.warnings.length > 0 ? (
        <p className="mt-3 text-sm text-[var(--vpw-text-secondary)]">
          {parserPreview.warnings.join(" ")}
        </p>
      ) : null}
    </div>
  )
}

function ReadinessList({
  readiness,
}: {
  readiness: readonly ImportReadinessCheck[]
}) {
  return (
    <div className="mt-3 grid gap-2 sm:grid-cols-2">
      {readiness.map((check) => (
        <div
          className="flex items-start gap-2 rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-panel)] px-3 py-2"
          key={check.id}
        >
          <ReadinessIcon status={check.status} />
          <div className="min-w-0">
            <p className="font-medium text-[var(--vpw-text-primary)]">
              {check.label}
            </p>
            {check.message ? (
              <p className="mt-0.5 text-xs text-[var(--vpw-text-secondary)]">
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
  const Icon =
    status === "passed"
      ? Check
      : status === "missing" || status === "error"
        ? X
        : Circle
  return (
    <Icon aria-hidden="true" className={`mt-0.5 size-4 shrink-0 ${className}`} />
  )
}

function PreviewSummary({ parserPreview }: { parserPreview: ParserPreview }) {
  return (
    <VpwKeyValueList
      className="mt-3"
      density="compact"
      items={[
        {
          label: "Candidate findings",
          value: parserPreview.candidateRows ?? "Available after import",
        },
        { label: "Updated findings", value: "Available after import" },
        {
          label: "Ignored lines",
          value: parserPreview.ignoredRows ?? "Available after import",
        },
        { label: "Warnings", value: parserPreview.warnings.length },
        { label: "Preview mode", value: "Shallow local check" },
      ]}
    />
  )
}
