import { Link } from "@/lib/router"
import {
  Check,
  CheckCircle2,
  Circle,
  X,
} from "lucide-react"
import type { CSSProperties } from "react"
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
  VpwStatusBanner,
} from "@/components/vpw"
import { cn } from "@/lib/utils"
import {
  FORMAT_CATEGORY_LABELS,
  getImportFormat,
  SUPPORTED_IMPORT_FORMATS,
  type ImportInputType,
  type ImportReadinessCheck,
  type ParserPreview,
  type SupportedFormat,
  type SupportedFormatCategory,
} from "@/lib/import-format-metadata"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import { FileUploadField } from "./ImportsWorkbenchFileUploadField"
import { ProviderAttackOptions } from "./ImportsWorkbenchProviderOptions"
import {
  fileSizeLabel,
  hasOptionalContext,
  optionalContextLabels,
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

const importSourceColorVars: Record<ImportInputType, string> = {
  "cve-list": "var(--vpw-source-cve)",
  "generic-occurrence-csv": "var(--vpw-source-csv)",
  "trivy-json": "var(--vpw-source-trivy)",
  "grype-json": "var(--vpw-source-grype)",
  "cyclonedx-json": "var(--vpw-source-cyclonedx)",
  "spdx-json": "var(--vpw-source-spdx)",
  "dependency-check-json": "var(--vpw-source-dependency-check)",
  "github-alerts-json": "var(--vpw-source-github)",
  "nessus-xml": "var(--vpw-source-nessus)",
  "openvas-xml": "var(--vpw-source-openvas)",
}

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
    <VpwPanel className="overflow-hidden p-0 lg:h-full">
      <ol className="relative flex flex-col gap-1 p-4">
        {stepLabels.map((item, index) => {
          const reachable =
            item.id === 1 ||
            (item.id === 2 && canReachStep2) ||
            (item.id === 3 && canReachStep3) ||
            (item.id === 4 && canReachStep4)
          const completed = item.id < currentStep
          const active = item.id === currentStep
          const blockedReason = reachable
            ? ""
            : blockedStepReason(item.id, canReachStep2, canReachStep3)
          return (
            <li className="relative" key={item.id}>
              {index < stepLabels.length - 1 ? (
                <span
                  aria-hidden="true"
                  className="absolute top-9 bottom-[-0.65rem] left-4 w-px bg-[var(--vpw-border-default)]"
                />
              ) : null}
              <button
                aria-current={active ? "step" : undefined}
                className={cn(
                  "relative z-10 grid min-h-[4.75rem] w-full grid-cols-[2rem_minmax(0,1fr)] items-start gap-3 rounded-[var(--vpw-radius-lg)] border px-0 py-3 text-left transition-[background,border-color,box-shadow]",
                  active
                    ? "border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] shadow-[var(--vpw-shadow-1)]"
                    : "border-transparent bg-transparent",
                  reachable
                    ? "hover:border-[var(--vpw-border-default)] hover:bg-[var(--vpw-bg-panel)]"
                    : "cursor-not-allowed",
                )}
                disabled={!reachable}
                onClick={() => reachable && onStepChange(item.id)}
                type="button"
              >
                <span
                  className={cn(
                    "relative z-10 flex size-8 shrink-0 items-center justify-center rounded-full border bg-[var(--vpw-bg-card)] font-mono text-xs font-semibold",
                    completed &&
                      "border-[var(--vpw-green)] bg-[var(--vpw-bg-success)] text-[var(--vpw-green)]",
                    active &&
                      !completed &&
                      "border-[var(--vpw-green)] bg-[var(--vpw-green)] text-[var(--vpw-bg-card)]",
                    !active &&
                      !completed &&
                      "border-[var(--vpw-border-strong)] text-[var(--vpw-text-muted)]",
                  )}
                >
                  {completed ? (
                    <Check aria-hidden="true" className="size-4" />
                  ) : (
                    item.id
                  )}
                </span>
                <span className="min-w-0 pt-0.5">
                  <span
                    className={cn(
                      "block text-sm font-semibold leading-5",
                      active
                        ? "text-[var(--vpw-text-primary)]"
                        : "text-[var(--vpw-text-secondary)]",
                    )}
                  >
                    {item.label}
                  </span>
                  <span className="mt-0.5 block text-xs leading-5 text-[var(--vpw-text-muted)]">
                    {blockedReason || item.description}
                  </span>
                </span>
              </button>
            </li>
          )
        })}
      </ol>
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
          <SelectTrigger
            aria-label="Import project"
            className="h-12"
            id="import-project"
          >
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
                <FormatOptionCard
                  checked={importWizard.inputType === format.inputType}
                  format={format}
                  key={format.inputType}
                  onClick={() => onInputTypeChange(format.inputType)}
                />
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  )
}

function FormatOptionCard({
  checked,
  format,
  onClick,
}: {
  checked: boolean
  format: SupportedFormat
  onClick: () => void
}) {
  const extensions = format.extensions.join(", ")

  return (
    <Button
      aria-pressed={checked}
      className={cn(
        "group flex h-auto min-h-[5.4rem] w-full items-center justify-between gap-4 whitespace-normal rounded-[var(--vpw-radius-lg)] border bg-[var(--vpw-bg-card)] p-4 text-left shadow-[var(--vpw-shadow-0)] transition-[background,border-color,box-shadow]",
        checked
          ? "border-[var(--vpw-green)] bg-[color-mix(in_srgb,var(--vpw-bg-success)_54%,var(--vpw-bg-card))] shadow-[var(--vpw-shadow-1)] ring-1 ring-[color-mix(in_srgb,var(--vpw-green)_18%,transparent)]"
          : "border-[var(--vpw-border-default)] hover:border-[var(--vpw-border-strong)] hover:bg-[var(--vpw-bg-panel)]",
      )}
      onClick={onClick}
      type="button"
      variant="outline"
    >
      <span className="flex min-w-0 items-center gap-4">
        <ImportSourceMark checked={checked} inputType={format.inputType} />
        <span className="min-w-0">
          <span className="block font-semibold leading-5 text-[var(--vpw-text-primary)]">
            {format.label}
          </span>
          <span className="mt-1 block text-xs leading-4 text-[var(--vpw-text-muted)]">
            {extensions}
          </span>
          <span className="mt-1 block text-sm leading-5 text-[var(--vpw-text-secondary)]">
            {format.shortDescription}
          </span>
        </span>
      </span>
      {checked ? (
        <CheckCircle2
          aria-hidden="true"
          className="size-5 shrink-0 text-[var(--vpw-green)]"
        />
      ) : (
        <Circle
          aria-hidden="true"
          className="size-5 shrink-0 text-[var(--vpw-text-muted)]"
        />
      )}
    </Button>
  )
}

function ImportSourceMark({
  checked,
  inputType,
}: {
  checked: boolean
  inputType: ImportInputType
}) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        "flex size-10 shrink-0 items-center justify-center rounded-[var(--vpw-radius-md)] border bg-[var(--vpw-bg-card)] text-[var(--import-source-color)]",
        checked
          ? "border-[color-mix(in_srgb,var(--import-source-color)_30%,var(--vpw-bg-card))]"
          : "border-[var(--vpw-border-subtle)]",
      )}
      style={
        {
          "--import-source-color": importSourceColorVars[inputType],
        } as CSSProperties
      }
    >
      <ImportSourceGlyph inputType={inputType} />
    </span>
  )
}

function ImportSourceGlyph({ inputType }: { inputType: ImportInputType }) {
  switch (inputType) {
    case "cve-list":
      return (
        <svg
          aria-hidden="true"
          className="size-5"
          fill="none"
          focusable="false"
          viewBox="0 0 24 24"
        >
          <path
            d="M7 3.5h7.3L18 7.2v13.3H7z"
            stroke="currentColor"
            strokeLinejoin="round"
            strokeWidth="1.8"
          />
          <path
            d="M14.2 3.8v3.7h3.6M9.5 11h5M9.5 14h5M9.5 17h3.2"
            stroke="currentColor"
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="1.8"
          />
        </svg>
      )
    case "generic-occurrence-csv":
      return (
        <svg
          aria-hidden="true"
          className="size-5"
          fill="none"
          focusable="false"
          viewBox="0 0 24 24"
        >
          <path
            d="M5 5h14v14H5zM5 10h14M5 14h14M10 5v14"
            stroke="currentColor"
            strokeLinejoin="round"
            strokeWidth="1.8"
          />
        </svg>
      )
    case "trivy-json":
      return (
        <svg
          aria-hidden="true"
          className="size-6"
          fill="none"
          focusable="false"
          viewBox="0 0 32 32"
        >
          <path
            d="M16 3 28 10.5 16 29 4 10.5z"
            stroke="currentColor"
            strokeLinejoin="round"
            strokeWidth="2.2"
          />
          <path
            d="m4 10.5 12 5.1 12-5.1M16 3v12.6M10.6 13.3 16 29l5.4-15.7"
            stroke="currentColor"
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="1.8"
          />
        </svg>
      )
    case "grype-json":
      return (
        <svg
          aria-hidden="true"
          className="size-6"
          fill="none"
          focusable="false"
          viewBox="0 0 32 32"
        >
          <path
            d="M5 17.5c1.9-5.2 7.1-8 13.2-7.1 4.6.7 7.8 3.7 8.8 7.2h2.2c-.9 3.8-3.8 6.3-8.6 7.2-6.3 1.2-12.8-1.1-15.6-7.3Z"
            stroke="currentColor"
            strokeLinejoin="round"
            strokeWidth="2"
          />
          <path
            d="M7.7 16.9c-1.8-.3-3.1-1.2-4-2.7M11.5 11.8l-1.9-3M17.8 10.4l1-3.4M23.6 13.1l2.9-2"
            stroke="currentColor"
            strokeLinecap="round"
            strokeWidth="1.8"
          />
          <circle cx="22.3" cy="17.2" r="1.2" fill="currentColor" />
        </svg>
      )
    case "dependency-check-json":
      return (
        <span className="font-mono text-base font-black tracking-normal">
          DC
        </span>
      )
    case "github-alerts-json":
      return (
        <svg
          aria-hidden="true"
          className="size-5"
          focusable="false"
          viewBox="0 0 16 16"
        >
          <path
            clipRule="evenodd"
            d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82A7.7 7.7 0 0 1 8 3.87c.68 0 1.36.09 2 .26 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8Z"
            fill="currentColor"
            fillRule="evenodd"
          />
        </svg>
      )
    case "cyclonedx-json":
      return (
        <svg
          aria-hidden="true"
          className="size-6"
          fill="none"
          focusable="false"
          viewBox="0 0 32 32"
        >
          <path
            d="M23.7 9.3a10 10 0 1 0 0 13.4M21.3 12.2a6.2 6.2 0 1 0 0 7.6"
            stroke="currentColor"
            strokeLinecap="round"
            strokeWidth="2.4"
          />
          <path
            d="M23 12h4v8h-4z"
            stroke="currentColor"
            strokeLinejoin="round"
            strokeWidth="1.8"
          />
        </svg>
      )
    case "spdx-json":
      return (
        <span className="font-mono text-sm font-black tracking-normal">
          SPDX
        </span>
      )
    case "nessus-xml":
      return (
        <svg
          aria-hidden="true"
          className="size-6"
          fill="none"
          focusable="false"
          viewBox="0 0 32 32"
        >
          <path
            d="M3.5 16s4.6-7 12.5-7 12.5 7 12.5 7-4.6 7-12.5 7S3.5 16 3.5 16Z"
            stroke="currentColor"
            strokeLinejoin="round"
            strokeWidth="2.2"
          />
          <circle cx="16" cy="16" r="4.2" stroke="currentColor" strokeWidth="2.2" />
          <circle cx="16" cy="16" r="1.4" fill="currentColor" />
        </svg>
      )
    case "openvas-xml":
      return (
        <svg
          aria-hidden="true"
          className="size-6"
          fill="none"
          focusable="false"
          viewBox="0 0 32 32"
        >
          <path
            d="M7.5 20.5c3.7 3.3 9.7 3.4 13.6.4 2.2-1.7 3.3-4 3.3-6.7 2 .5 3.4 1.8 4.1 3.8.1-5.3-4-9.4-9.3-9.7l1.8-3.5-5.5 3.7c-4.5.5-8.2 3.7-9 8.2l-3 1.2z"
            stroke="currentColor"
            strokeLinejoin="round"
            strokeWidth="1.9"
          />
          <path
            d="M13.4 13.5h.1M19.6 13.5h.1M11.7 19.4c2.8 1.2 5.8 1.2 8.7 0"
            stroke="currentColor"
            strokeLinecap="round"
            strokeWidth="2.1"
          />
        </svg>
      )
    default:
      return null
  }
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
  const uploadHelp =
    format?.value === "generic-occurrence-csv"
      ? "Your CSV must include a CVE identifier for each row. Optional columns can add component or asset context."
      : "Attach the supplied evidence export for the selected input type."

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
        description={uploadHelp}
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
  const attackContextCheck = props.readiness.find(
    (check) => check.id === "attack-context",
  )
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
      {attackContextCheck?.status === "error" ? (
        <VpwStatusBanner title="ATT&CK context needs attention" tone="critical">
          {attackContextCheck.message}
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
  importFailed = false,
  inputTypeLabel,
  parserPreview,
  props,
  readiness,
  step,
}: {
  importFailed?: boolean
  inputTypeLabel: string
  parserPreview: ParserPreview
  props: ImportsWorkbenchProps
  readiness: readonly ImportReadinessCheck[]
  step: StepId
}) {
  return (
    <VpwPanel
      className="import-summary-rail flex flex-col gap-4 lg:h-full min-[1600px]:sticky min-[1600px]:top-6"
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
            label: "Asset context",
            value: props.importWizard.assetContextFile?.name ?? "Not selected",
          },
          {
            label: "VEX",
            value: props.importWizard.vexFile?.name ?? "Not selected",
          },
          {
            label: "ATT&CK context",
            value:
              props.importWizard.attackSource &&
              props.importWizard.attackSource !== "none"
                ? "Reviewed defensive context configured"
                : "Not selected",
          },
          {
            label: "Provider data",
            value: props.importWizard.providerSnapshotFile
              ? props.importWizard.providerSnapshotFile
              : "Current provider data",
          },
          {
            label: "Deterministic replay",
            value: props.importWizard.lockedProviderData ? "Yes" : "No",
          },
          {
            label: "Readiness",
            value: readinessCopyForStep(step, readiness, importFailed),
            tone: readinessToneForStep(step, readiness, importFailed),
          },
        ]}
      />
      <div className="flex flex-wrap gap-2">
        {hasOptionalContext(props.importWizard)
          ? optionalContextLabels(props.importWizard).map((label) => (
              <MetaTag key={label} label={label} />
            ))
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
