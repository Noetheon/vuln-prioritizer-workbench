import { Link } from "@/lib/router"
import {
  Check,
  CheckCircle2,
  ChevronRight,
  Circle,
  Info,
  ShieldCheck,
  Table2,
  X,
} from "lucide-react"
import type { CSSProperties, ReactNode } from "react"
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
      <ol className="relative flex flex-col gap-1.5 p-3">
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
          const accessibleDescription = blockedReason || item.description
          const visualDescription =
            blockedReason === "Select project and input type first."
              ? "Choose source first."
              : blockedReason === "Upload a valid evidence file first."
                ? "Upload evidence first."
                : accessibleDescription
          return (
            <li className="relative" key={item.id}>
              {index < stepLabels.length - 1 ? (
                <span
                  aria-hidden="true"
                  className={cn(
                    "absolute top-8 bottom-[-0.85rem] left-[1.55rem] w-px",
                    completed
                      ? "bg-[var(--vpw-green)]"
                      : "bg-[var(--vpw-border-default)]",
                  )}
                />
              ) : null}
              <Button
                aria-current={active ? "step" : undefined}
                className={cn(
                  "relative z-10 grid h-auto min-h-[3.875rem] w-full grid-cols-[2.25rem_minmax(0,1fr)] items-center justify-start gap-2.5 rounded-[var(--vpw-radius-md)] px-2.5 py-2.5 text-left whitespace-normal transition-[background,box-shadow,color]",
                  active
                    ? "bg-[var(--vpw-bg-card)] shadow-[var(--vpw-shadow-1)] ring-1 ring-[var(--vpw-border-default)]"
                    : "bg-transparent",
                  reachable
                    ? "hover:bg-[var(--vpw-bg-panel)]"
                    : "cursor-not-allowed opacity-80",
                )}
                disabled={!reachable}
                onClick={() => reachable && onStepChange(item.id)}
                size="default"
                title={blockedReason || undefined}
                type="button"
                variant="ghost"
              >
                <span
                  className={cn(
                    "relative z-10 flex size-7 shrink-0 items-center justify-center rounded-full border bg-[var(--vpw-bg-card)] font-mono text-[0.72rem] font-semibold",
                    completed &&
                      "border-[var(--vpw-green)] bg-[var(--vpw-green)] text-[var(--vpw-bg-card)]",
                    active &&
                      !completed &&
                      "border-[var(--vpw-green)] bg-[var(--vpw-green)] text-[var(--vpw-bg-card)]",
                    !active &&
                      !completed &&
                      "border-[var(--vpw-border-strong)] text-[var(--vpw-text-muted)]",
                  )}
                >
                  {completed ? (
                    <Check aria-hidden="true" className="size-3.5" />
                  ) : (
                    item.id
                  )}
                </span>
                <span className="min-w-0">
                  <span
                    className={cn(
                      "block text-[0.8125rem] font-semibold leading-4",
                      active
                        ? "text-[var(--vpw-text-primary)]"
                        : "text-[var(--vpw-text-secondary)]",
                    )}
                  >
                    {item.label}
                  </span>
                  <span className="mt-1 block text-[0.72rem] leading-4 text-[var(--vpw-text-muted)]">
                    {visualDescription}
                  </span>
                </span>
              </Button>
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
        <span className="font-mono text-base font-black">
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
        <span className="font-mono text-sm font-black">
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
  const metadataFormat = getImportFormat(importWizard.inputType)
  const uploadRequirement = metadataFormat
    ? uploadRequirementCopy(metadataFormat.inputType)
    : "Attach the main evidence file."

  return (
    <section className="flex flex-col gap-4">
      <VpwSectionHeader
        description="Attach evidence for the selected import format before continuing."
        title="Upload file"
      />
      <div className="rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-3">
        <div className="mb-3">
          <p className="text-base font-semibold text-[var(--vpw-text-primary)]">
            A. Evidence file
          </p>
          <p className="mt-1 text-sm text-[var(--vpw-text-secondary)]">
            <span className="font-medium text-[var(--vpw-text-primary)]">
              {format?.label ?? "Input type not selected"}
            </span>
            {metadataFormat ? ` - ${uploadRequirement}` : ""}
          </p>
        </div>
        <FileUploadField
          accept={format?.accept}
          description={undefined}
          file={importWizard.file}
          fieldClassName="[&_[data-slot=field-label]]:sr-only"
          id="import-file"
          label="Evidence file"
          name="importFile"
          onFileChange={onFileChange}
          required
          selectedTone={importWizard.file ? "accepted" : "default"}
          showAcceptedText={false}
          showSelectedFileDescription={false}
        />
        {!importWizard.file && metadataFormat?.extensions.length ? (
          <AcceptedTypeChips extensions={metadataFormat.extensions} />
        ) : null}
      </div>
      <div className="rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-3">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-base font-semibold text-[var(--vpw-text-primary)]">
              B. File check
            </p>
            <p className="mt-1 text-sm text-[var(--vpw-text-secondary)]">
              Shallow validation runs locally before the import starts.
            </p>
          </div>
          {parserPreview.state === "passed" || parserPreview.state === "warning" ? (
            <VpwBadge tone={parserPreview.state === "warning" ? "warning" : "success"}>
              {parserPreview.state === "warning" ? "Warning" : "Passed"}
            </VpwBadge>
          ) : null}
        </div>
        <ParserPreviewPanel parserPreview={parserPreview} />
      </div>
    </section>
  )
}

function AcceptedTypeChips({ extensions }: { extensions: readonly string[] }) {
  return (
    <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-[var(--vpw-text-muted)]">
      <span className="font-medium text-[var(--vpw-text-secondary)]">
        Accepted file types:
      </span>
      {extensions.map((extension) => (
        <span
          className="rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-panel)] px-2 py-1 font-mono text-[var(--vpw-text-primary)]"
          key={extension}
        >
          {extension}
        </span>
      ))}
    </div>
  )
}

function uploadRequirementCopy(inputType: ImportInputType) {
  switch (inputType) {
    case "cve-list":
      return "One CVE identifier per line or a supported CVE column."
    case "generic-occurrence-csv":
      return "Rows must include a CVE identifier; asset and component columns are optional."
    case "trivy-json":
      return "Use a Trivy vulnerability report export."
    case "grype-json":
      return "Use a Grype vulnerability report export."
    case "dependency-check-json":
      return "Use an OWASP Dependency-Check report export."
    case "github-alerts-json":
      return "Use the pinned GitHub alert export shape."
    case "cyclonedx-json":
      return "Include components plus vulnerability references."
    case "spdx-json":
      return "Use package inventory data with vulnerability references where supported."
    case "nessus-xml":
      return "Use Nessus ReportHost and ReportItem evidence."
    case "openvas-xml":
      return "Use OpenVAS result evidence with CVE data."
  }
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
  const assetContextReady = assetContextCheck?.status === "passed"
  const vexReady = vexCheck?.status === "passed"
  return (
    <section className="flex flex-col gap-5">
      <VpwSectionHeader
        description="Optional context can improve prioritization and explanations. You can skip this step."
        title="Add context (optional)"
      />
      <div className="grid gap-4 md:grid-cols-2">
        <FileUploadField
          accept=".csv,text/csv"
          acceptedLabel=".csv"
          description="Owner, service, environment, exposure, and criticality context."
          emptyIcon={<Table2 aria-hidden="true" className="size-5" />}
          file={props.importWizard.assetContextFile}
          id="asset-context-file"
          label="Asset context CSV"
          layout="centered"
          name="assetContextFile"
          onFileChange={props.onAssetContextFileChange}
          selectedDescription={optionalFileDescription(
            assetContextCheck?.status,
            "CSV header detected.",
          )}
          selectedTone={assetContextReady ? "accepted" : "default"}
          showSelectedFileDescription={false}
        />
        <FileUploadField
          accept=".json,application/json"
          acceptedLabel=".json"
          description="OpenVEX or CycloneDX VEX sidecar."
          emptyIcon={<ShieldCheck aria-hidden="true" className="size-5" />}
          file={props.importWizard.vexFile}
          id="vex-file"
          label="VEX overlay"
          layout="centered"
          name="vexFile"
          onFileChange={props.onVexFileChange}
          selectedDescription={optionalFileDescription(
            vexCheck?.status,
            "JSON parsed.",
          )}
          selectedTone={vexReady ? "accepted" : "default"}
          showSelectedFileDescription={false}
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
      <div className="flex items-start gap-3 rounded-[var(--vpw-radius-lg)] border border-[color-mix(in_srgb,var(--vpw-blue)_32%,var(--vpw-border-default))] bg-[var(--vpw-bg-info)] p-4 text-sm text-[var(--vpw-text-secondary)]">
        <Info
          aria-hidden="true"
          className="mt-0.5 size-5 shrink-0 text-[var(--vpw-blue)]"
        />
        <div>
          <p className="font-semibold text-[var(--vpw-blue)]">
            ATT&CK/TTP context
          </p>
          <p className="mt-1 leading-6">
            Adds reviewed defensive ATT&CK mappings where available. Unmapped
            CVEs remain unmapped, and this context does not override base priority.
          </p>
        </div>
      </div>
      <details className="group rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)]">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-sm font-semibold text-[var(--vpw-text-primary)] [&::-webkit-details-marker]:hidden">
          <span className="inline-flex min-w-0 items-center gap-2">
            <ChevronRight
              aria-hidden="true"
              className="size-4 shrink-0 text-[var(--vpw-text-muted)] transition-transform group-open:rotate-90"
            />
            <span>Advanced provider data and reviewed ATT&CK context</span>
          </span>
            <span className="rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-info)] px-2 py-1 font-mono text-xs text-[var(--vpw-blue)]">
              Optional
            </span>
        </summary>
        <div className="border-t border-[var(--vpw-border-default)] p-3 sm:p-4">
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

function optionalFileDescription(
  status: ImportReadinessCheck["status"] | undefined,
  successMessage: string,
) {
  if (status === "passed") return successMessage
  if (status === "pending") return "Checking file."
  if (status === "error") return "Needs attention."
  return undefined
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
  const blockingChecks = readiness.filter(
    (check) => check.status === "missing" || check.status === "error",
  )
  const requiredChecks = readiness.filter(
    (check) =>
      check.id !== "asset-context" &&
      check.id !== "vex" &&
      check.id !== "attack-context",
  )
  const requiredPassed = requiredChecks.filter(
    (check) => check.status === "passed" || check.status === "warning",
  ).length
  const optionalChecks = readiness.filter(
    (check) =>
      check.id === "asset-context" ||
      check.id === "vex" ||
      check.id === "attack-context",
  )
  const optionalSelected = optionalChecks.filter((check) => check.status === "passed")
  const providerCheck = readiness.find((check) => check.id === "provider-data")
  const contextSummary =
    optionalSelected.length > 0
      ? optionalSelected.map((check) => check.label).join(", ")
      : "No optional context selected"
  const providerMessage =
    providerCheck?.message ?? "Current provider data is available."
  const evidenceFileLabel = importWizard.file
    ? `${importWizard.file.name} - ${fileSizeLabel(importWizard.file)}`
    : "Required"
  const settingsItems = [
    { label: "Project", value: selectedProject?.name ?? "Required" },
    { label: "Input type", value: format?.label ?? "Required" },
    {
      label: "Evidence file",
      value: evidenceFileLabel,
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
      muted: !importWizard.assetContextFile,
    },
    {
      label: "VEX",
      value: importWizard.vexFile?.name ?? "Not selected",
      muted: !importWizard.vexFile,
    },
    {
      label: "ATT&CK context",
      value:
        importWizard.attackSource && importWizard.attackSource !== "none"
          ? "Reviewed defensive context configured"
          : "Not selected",
      muted: !importWizard.attackSource || importWizard.attackSource === "none",
    },
    {
      label: "Deterministic replay",
      value: importWizard.lockedProviderData ? "Yes" : "No",
      muted: !importWizard.lockedProviderData,
    },
  ]
  return (
    <section className="flex flex-col gap-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <VpwSectionHeader
          description="Confirm the import package and start the recorded run."
          title="Review import"
        />
        <VpwBadge tone={blockingChecks.length === 0 ? "success" : "critical"}>
          {blockingChecks.length === 0 ? "Ready" : "Blocked"}
        </VpwBadge>
      </div>
      <ReviewPreflightSummary
        blockingCount={blockingChecks.length}
        optionalContext={contextSummary}
        providerMessage={providerMessage}
        requiredPassed={requiredPassed}
        requiredTotal={requiredChecks.length}
      />
      <ReviewPackageSummary
        evidenceFile={evidenceFileLabel}
        inputType={format?.label ?? "Required"}
        projectName={selectedProject?.name ?? "Required"}
      />
      <div className="grid gap-4 min-[1800px]:grid-cols-[minmax(0,1.05fr)_minmax(18rem,0.95fr)] min-[1800px]:items-start">
        <section className="min-w-0">
          <ReviewSectionHeading
            description="Required checks are ready before the import starts."
            title="Preflight checks"
          />
          <ReadinessOverview readiness={readiness} />
        </section>
        <section className="min-w-0">
          <ReviewSectionHeading
            description="Shallow local validation only. Final parser results are recorded after import."
            title="Preview"
          />
          <PreviewSummary parserPreview={parserPreview} />
        </section>
      </div>
      <details className="group min-w-0 border-t border-[var(--vpw-border-subtle)] pt-3">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-left [&::-webkit-details-marker]:hidden">
          <span className="min-w-0">
            <span className="block text-base font-semibold text-[var(--vpw-text-primary)]">
              Import settings
            </span>
            <span className="mt-1 block text-sm leading-5 text-[var(--vpw-text-secondary)]">
              Full run metadata attached to this import.
            </span>
          </span>
          <ChevronRight
            aria-hidden="true"
            className="size-4 shrink-0 text-[var(--vpw-text-muted)] transition-transform group-open:rotate-90"
          />
        </summary>
        <SettingsSummaryList items={settingsItems} />
      </details>
    </section>
  )
}

function ReviewPreflightSummary({
  blockingCount,
  optionalContext,
  providerMessage,
  requiredPassed,
  requiredTotal,
}: {
  blockingCount: number
  optionalContext: string
  providerMessage: string
  requiredPassed: number
  requiredTotal: number
}) {
  const ready = blockingCount === 0
  return (
    <div
      className={cn(
        "rounded-[var(--vpw-radius-lg)] border p-3",
        ready
          ? "border-[color-mix(in_srgb,var(--vpw-green)_24%,var(--vpw-border-default))] bg-[color-mix(in_srgb,var(--vpw-bg-success)_54%,var(--vpw-bg-card))]"
          : "border-[color-mix(in_srgb,var(--vpw-red)_34%,var(--vpw-border-default))] bg-[color-mix(in_srgb,var(--vpw-bg-critical)_50%,var(--vpw-bg-card))]",
      )}
    >
      <div className="grid gap-3">
        <div className="flex min-w-0 items-start gap-3">
          <span
            className={cn(
              "grid size-8 shrink-0 place-items-center rounded-full border",
              ready
                ? "border-[color-mix(in_srgb,var(--vpw-green)_28%,transparent)] bg-[var(--vpw-bg-card)] text-[var(--vpw-green)]"
                : "border-[color-mix(in_srgb,var(--vpw-red)_28%,transparent)] bg-[var(--vpw-bg-card)] text-[var(--vpw-red)]",
            )}
          >
            {ready ? (
              <CheckCircle2 aria-hidden="true" className="size-5" />
            ) : (
              <X aria-hidden="true" className="size-5" />
            )}
          </span>
          <div className="min-w-0">
            <p className="font-semibold text-[var(--vpw-text-primary)]">
              {ready ? "Ready to import" : "Review required"}
            </p>
            <p className="mt-1 max-w-[34rem] text-sm leading-5 text-[var(--vpw-text-secondary)]">
              {ready
                ? "Required checks passed. Starting the import creates a recorded run."
                : `${blockingCount} check${blockingCount === 1 ? "" : "s"} need attention before import.`}
            </p>
          </div>
        </div>
        <dl className="grid min-w-0 gap-2 text-sm sm:grid-cols-3">
          <ReviewMetric
            label="Required"
            tone={ready ? "success" : "critical"}
            value={
              ready
                ? `${requiredPassed}/${requiredTotal} passed`
                : `${blockingCount} blocked`
            }
          />
          <ReviewMetric label="Context" value={optionalContext} />
          <ReviewMetric label="Provider" value={providerMessage} />
        </dl>
      </div>
    </div>
  )
}

function ReviewPackageSummary({
  evidenceFile,
  inputType,
  projectName,
}: {
  evidenceFile: string
  inputType: string
  projectName: string
}) {
  return (
    <dl className="grid rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-panel)] text-sm md:grid-cols-[minmax(0,1fr)_minmax(0,0.9fr)_minmax(0,1.35fr)] md:divide-x md:divide-[var(--vpw-border-subtle)]">
      <ReviewMetric label="Project" value={projectName} />
      <ReviewMetric label="Input type" value={inputType} />
      <ReviewMetric label="Evidence file" value={evidenceFile} />
    </dl>
  )
}

function ReadinessOverview({
  readiness,
}: {
  readiness: readonly ImportReadinessCheck[]
}) {
  const visibleChecks = readiness.filter(
    (check) =>
      check.id !== "asset-context" &&
      check.id !== "vex" &&
      check.id !== "attack-context",
  )
  const contextChecks = readiness.filter(
    (check) =>
      (check.id === "asset-context" ||
        check.id === "vex" ||
        check.id === "attack-context") &&
      (check.status === "passed" ||
        check.status === "warning" ||
        check.status === "error"),
  )
  return (
    <div className="mt-3">
      <div className="grid gap-2 sm:grid-cols-3">
        {visibleChecks.map((check) => (
          <ReadinessCompactRow check={check} key={check.id} />
        ))}
      </div>
      {contextChecks.length > 0 ? (
        <details className="group mt-3">
          <summary className="inline-flex cursor-pointer list-none items-center gap-2 text-sm font-medium text-[var(--vpw-text-secondary)] transition-colors hover:text-[var(--vpw-text-primary)] [&::-webkit-details-marker]:hidden">
            <ChevronRight
              aria-hidden="true"
              className="size-4 transition-transform group-open:rotate-90"
            />
            Context checks
          </summary>
          <div className="mt-2 grid gap-2 sm:grid-cols-3">
            {contextChecks.map((check) => (
              <ReadinessCompactRow check={check} key={check.id} />
            ))}
          </div>
        </details>
      ) : null}
      <details className="group mt-3">
        <summary className="inline-flex cursor-pointer list-none items-center gap-2 text-xs font-medium text-[var(--vpw-text-muted)] transition-colors hover:text-[var(--vpw-text-primary)] [&::-webkit-details-marker]:hidden">
          <ChevronRight
            aria-hidden="true"
            className="size-4 transition-transform group-open:rotate-90"
          />
          Full validation log
        </summary>
        <ReadinessList readiness={readiness} />
      </details>
    </div>
  )
}

function ReadinessCompactRow({ check }: { check: ImportReadinessCheck }) {
  return (
    <div
      className="flex min-w-0 items-center gap-2 rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-3 py-2"
      title={check.message || readinessStatusLabel(check.status)}
    >
      <ReadinessIcon status={check.status} />
      <span className="min-w-0 truncate text-sm font-medium leading-5 text-[var(--vpw-text-primary)]">
        {readinessShortLabel(check)}
      </span>
      <span className="sr-only">
        {check.message || readinessStatusLabel(check.status)}
      </span>
    </div>
  )
}

function readinessShortLabel(check: ImportReadinessCheck) {
  switch (check.id) {
    case "project":
      return "Project selected"
    case "input-type":
      return "Input type selected"
    case "evidence-file":
      return "Evidence uploaded"
    case "file-type":
      return "File type checked"
    case "parser-preview":
      return "Preview ready"
    case "provider-data":
      return "Provider data ready"
    case "asset-context":
      return "Asset context checked"
    case "vex":
      return "VEX checked"
    case "attack-context":
      return "ATT&CK context checked"
    default:
      return check.label
  }
}

function readinessStatusLabel(status: ImportReadinessCheck["status"]) {
  if (status === "passed") return "Ready."
  if (status === "warning") return "Warning, import can continue."
  if (status === "missing") return "Required before import."
  if (status === "error") return "Needs attention."
  return "Pending."
}

function ReviewSectionHeading({
  description,
  title,
}: {
  description: string
  title: string
}) {
  return (
    <div>
      <h3 className="text-base font-semibold text-[var(--vpw-text-primary)]">
        {title}
      </h3>
      <p className="mt-1 text-sm leading-5 text-[var(--vpw-text-secondary)]">
        {description}
      </p>
    </div>
  )
}

function ReviewMetric({
  label,
  tone,
  value,
}: {
  label: string
  tone?: "critical" | "success"
  value: ReactNode
}) {
  return (
    <div className="min-w-0 px-3 py-2 md:first:pl-3 md:last:pr-3">
      <dt className="vpw-label">{label}</dt>
      <dd
        className={cn(
          "mt-1 min-w-0 font-medium leading-5 text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]",
          tone === "success" && "text-[var(--vpw-green)]",
          tone === "critical" && "text-[var(--vpw-red)]",
        )}
      >
        {value}
      </dd>
    </div>
  )
}

function SettingsSummaryList({
  items,
}: {
  items: readonly { label: string; muted?: boolean; value: ReactNode }[]
}) {
  return (
    <dl className="mt-3 border-t border-[var(--vpw-border-subtle)] text-sm">
      {items.map((item) => (
        <div
          className="grid gap-2 border-b border-[var(--vpw-border-subtle)] py-3 sm:grid-cols-[minmax(9rem,0.42fr)_minmax(0,1fr)]"
          key={item.label}
        >
          <dt className="vpw-label">{item.label}</dt>
          <dd
            className={cn(
              "min-w-0 font-medium text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]",
              item.muted && "text-[var(--vpw-text-secondary)]",
            )}
          >
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  )
}

export function SummaryRail({
  importFailed = false,
  inputTypeLabel,
  props,
  readiness,
  step,
}: {
  importFailed?: boolean
  inputTypeLabel: string
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
      <dl className="grid border-t border-[var(--vpw-border-subtle)] text-sm">
        {[
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
            muted: !props.importWizard.assetContextFile,
          },
          {
            label: "VEX",
            value: props.importWizard.vexFile?.name ?? "Not selected",
            muted: !props.importWizard.vexFile,
          },
          {
            label: "ATT&CK context",
            value:
              props.importWizard.attackSource &&
              props.importWizard.attackSource !== "none"
                ? "Reviewed defensive context configured"
                : "Not selected",
            muted:
              !props.importWizard.attackSource ||
              props.importWizard.attackSource === "none",
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
            muted: !props.importWizard.lockedProviderData,
          },
        ].map((item) => (
          <div
            className="border-b border-[var(--vpw-border-subtle)] py-3"
            key={item.label}
          >
            <dt className="vpw-label">{item.label}</dt>
            <dd
              className={cn(
                "mt-1 min-w-0 font-medium text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]",
                item.muted && "text-[var(--vpw-text-secondary)]",
              )}
            >
              {item.value}
            </dd>
          </div>
        ))}
        <div className="border-b border-[var(--vpw-border-subtle)] py-3">
          <dt className="vpw-label">Readiness</dt>
          <dd className="mt-2">
            <VpwBadge tone={readinessToneForStep(step, readiness, importFailed)}>
              {readinessCopyForStep(step, readiness, importFailed)}
            </VpwBadge>
          </dd>
        </div>
      </dl>
      <div className="flex flex-wrap gap-2 pt-1">
        {hasOptionalContext(props.importWizard)
          ? optionalContextLabels(props.importWizard).map((label) => (
              <MetaTag key={label} label={label} />
            ))
          : null}
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
  const previewItems: Array<{
    label: string
    tone?: "warning" | "critical"
    value: number | string
  }> = [
    {
      label: "File type match",
      value: parserPreview.detectedInputType
        ? `${getImportFormat(parserPreview.detectedInputType)?.label ?? "Selected format"}`
        : "Matches selected format",
    },
    {
      label: "Required fields",
      value:
        parserPreview.requiredFieldsFound &&
        parserPreview.requiredFieldsFound.length > 0
          ? requiredFieldsPreviewLabel(parserPreview)
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
      tone: parserPreview.warnings.length > 0 ? "warning" : undefined,
      value: parserPreview.warnings.length,
    },
    {
      label: "Parser errors",
      tone: parserPreview.errors.length > 0 ? "critical" : undefined,
      value: parserPreview.errors.length,
    },
  ]
  return (
    <div>
      <div>
        <p className="font-semibold text-[var(--vpw-text-primary)]">
          {parserPreview.warnings.length > 0
            ? "Parser preview warning"
            : "Parser preview"}
        </p>
        <p className="mt-1 text-sm text-[var(--vpw-text-secondary)]">
          Full parser results will be available after import. If the file
          structure does not match the selected format, import may create fewer
          findings or skip rows.
        </p>
      </div>
      <dl className="mt-3 grid gap-px overflow-hidden rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-border-subtle)] text-sm md:grid-cols-2">
        {previewItems.map((item) => (
          <div
            className="grid min-h-10 grid-cols-[minmax(7.5rem,0.68fr)_minmax(0,1fr)] items-center gap-2.5 bg-[var(--vpw-bg-card)] px-3 py-1.5"
            key={item.label}
          >
            <dt className="vpw-label">{item.label}</dt>
            <dd
              className={cn(
                "min-w-0 font-medium text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]",
                item.tone === "warning" && "text-[var(--vpw-amber)]",
                item.tone === "critical" && "text-[var(--vpw-red)]",
              )}
            >
              {item.value}
            </dd>
          </div>
        ))}
      </dl>
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
    <div className="mt-3 overflow-hidden rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] text-sm">
      {readiness.map((check) => (
        <div
          className="grid gap-2 border-b border-[var(--vpw-border-subtle)] px-3 py-2.5 last:border-b-0 sm:grid-cols-[1.25rem_minmax(8rem,0.8fr)_minmax(0,1.2fr)] sm:items-start"
          key={check.id}
        >
          <ReadinessIcon status={check.status} />
          <p className="min-w-0 font-medium text-[var(--vpw-text-primary)]">
            {check.label}
          </p>
          {check.message ? (
            <p className="min-w-0 text-xs leading-5 text-[var(--vpw-text-secondary)] [overflow-wrap:anywhere] sm:text-right">
              {check.message}
            </p>
          ) : (
            <p className="text-xs leading-5 text-[var(--vpw-text-muted)] sm:text-right">
              No additional action.
            </p>
          )}
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
  const items: Array<{ label: string; tone?: "warning"; value: ReactNode }> = [
    {
      label: "Candidate findings",
      value: parserPreview.candidateRows ?? "Available after import",
    },
    { label: "Updated findings", value: "Available after import" },
    {
      label: "Ignored lines",
      value: parserPreview.ignoredRows ?? "Available after import",
    },
    {
      label: "Warnings",
      tone: parserPreview.warnings.length > 0 ? "warning" : undefined,
      value: parserPreview.warnings.length,
    },
  ]
  return (
    <dl className="mt-3 grid gap-px overflow-hidden rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-border-subtle)] text-sm sm:grid-cols-2">
      {items.map((item) => (
        <div
          className="grid min-h-16 gap-1 bg-[var(--vpw-bg-card)] px-3 py-2.5"
          key={item.label}
        >
          <dt className="vpw-label">{item.label}</dt>
          <dd
            className={cn(
              "min-w-0 text-base font-semibold leading-5 text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]",
              item.tone === "warning" && "text-[var(--vpw-amber)]",
            )}
          >
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  )
}

function requiredFieldsPreviewLabel(parserPreview: ParserPreview) {
  const fields = parserPreview.requiredFieldsFound ?? []
  if (fields.includes("CVE column")) return "cve_id column found"
  return fields.join(", ")
}
