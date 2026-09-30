import { Button } from "@/components/ui/button"
import { VpwStatusBanner } from "@/components/vpw"
import {
  getImportFormat,
  type ParserPreview,
  type SupportedFormat,
} from "@/lib/import-format-metadata"
import { cn } from "@/lib/utils"

export function AcceptedTypeChips({
  extensions,
}: {
  extensions: readonly string[]
}) {
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

export function ParserPreviewPanel({
  onUseDetectedType,
  parserPreview,
  supportedFormats,
}: {
  onUseDetectedType?: (inputType: string) => void
  parserPreview: ParserPreview
  supportedFormats: readonly SupportedFormat[]
}) {
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
    const detected = parserPreview.detectedInputType
    const detectedLabel = detected
      ? (getImportFormat(supportedFormats, detected)?.label ?? detected)
      : ""
    return (
      <VpwStatusBanner title="File cannot be prepared for import" tone="critical">
        <span className="flex flex-col items-start gap-2">
          <span>{parserPreview.errors.join(" ")}</span>
          {detected && onUseDetectedType ? (
            <Button
              onClick={() => onUseDetectedType(detected)}
              size="sm"
              type="button"
              variant="outline"
            >
              Use {detectedLabel}
            </Button>
          ) : null}
        </span>
      </VpwStatusBanner>
    )
  }
  const previewItems: Array<{
    label: string
    tone?: "warning" | "critical"
    value: number | string
  }> = [
    {
      label: "File content",
      value: fileContentPreviewLabel(parserPreview, supportedFormats),
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
      label: "Invalid lines",
      tone: (parserPreview.invalidRows ?? 0) > 0 ? "critical" : undefined,
      value: parserPreview.invalidRows ?? "Checked by full parser",
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

export function uploadRequirementCopy(format: SupportedFormat) {
  return format.minimumFields.length > 0
    ? format.minimumFields.join("; ")
    : format.expectedShape
}

function fileContentPreviewLabel(
  parserPreview: ParserPreview,
  supportedFormats: readonly SupportedFormat[],
) {
  if (parserPreview.detectedInputType) {
    const detected = getImportFormat(
      supportedFormats,
      parserPreview.detectedInputType,
    )
    return `Looks like ${detected?.label ?? parserPreview.detectedInputType}`
  }
  // CVE lists and occurrence CSVs are read line by line before the import.
  if (parserPreview.invalidRows !== undefined) return "Every CVE value checked"
  return "Checked by full parser after import"
}

function requiredFieldsPreviewLabel(parserPreview: ParserPreview) {
  const fields = parserPreview.requiredFieldsFound ?? []
  if (fields.includes("CVE column")) return "cve_id column found"
  return fields.join(", ")
}
