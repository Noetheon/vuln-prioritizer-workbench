import { ChevronRight, RefreshCcw } from "lucide-react"
import { Input } from "@/components/ui/input"
import {
  VpwBadge,
  VpwSectionHeader,
} from "@/components/vpw"
import {
  getImportFormat,
  type ImportReadinessCheck,
  type ParserPreview,
} from "@/lib/import-format-metadata"
import {
  fileSizeLabel,
  type ImportsWorkbenchProps,
} from "./imports-workbench-model"
import { PreviewSummary } from "./NewImportReviewPreview"
import { ReadinessOverview } from "./NewImportReviewReadiness"
import {
  ReviewPackageSummary,
  ReviewPreflightSummary,
} from "./NewImportReviewSummary"
import {
  ReviewSectionHeading,
  SettingsSummaryList,
} from "./NewImportReviewShared"

export function ReviewImportStep({
  importWizard,
  onResolveMissingChange,
  parserPreview,
  readiness,
  selectedProject,
  supportedFormats,
}: ImportsWorkbenchProps & {
  parserPreview: ParserPreview
  readiness: readonly ImportReadinessCheck[]
}) {
  const format = getImportFormat(supportedFormats, importWizard.inputType)
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
  const resolveMissing = importWizard.resolveMissing ?? true
  const evidenceFileLabel = importWizard.file
    ? `${importWizard.file.name} - ${fileSizeLabel(importWizard.file)}`
    : "Required"
  const settingsItems = [
    { label: "Project", value: selectedProject?.name ?? "Required" },
    { label: "Input type", value: format?.label ?? "Required" },
    ...(importWizard.sbomScanner === "grype"
      ? [
          { label: "SBOM scan", value: "Grype" },
          {
            label: "SBOM subject",
            value: importWizard.sbomTargetRef || "Required",
          },
          {
            label: "Database updates",
            value:
              importWizard.sbomDbUpdate === false
                ? "Disabled; installed database only"
                : "Allowed",
          },
        ]
      : []),
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
    {
      label: "Unreported findings",
      value: resolveMissing ? "Resolve" : "Keep open",
      muted: !resolveMissing,
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
      <label
        className="flex items-start gap-3 rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-4 text-sm"
        htmlFor="resolve-missing"
      >
        <Input
          checked={resolveMissing}
          className="mt-1 size-4 min-w-4 shrink-0 p-0 accent-[var(--vpw-blue)] shadow-none"
          id="resolve-missing"
          name="resolveMissing"
          onChange={(event) => onResolveMissingChange(event.target.checked)}
          type="checkbox"
        />
        <span className="min-w-0 pt-px">
          <span className="inline-flex items-center gap-2 font-semibold text-[var(--vpw-text-primary)]">
            <RefreshCcw
              aria-hidden="true"
              className="size-4 text-[var(--vpw-text-muted)]"
            />
            Resolve findings this import no longer reports
          </span>
          <span className="mt-0.5 block text-xs leading-5 text-[var(--vpw-text-muted)]">
            Findings an earlier import of the same format reported for a target
            in this file are marked resolved when this file no longer lists
            them. Turn this off for partial exports. A later import that
            reports a resolved finding again reopens it.
          </span>
        </span>
      </label>
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
