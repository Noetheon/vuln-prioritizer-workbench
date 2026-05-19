import { VpwStatusBanner } from "@/components/vpw"
import {
  getImportFormat,
  type ImportInputType,
  type ParserPreview,
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
  parserPreview,
}: {
  parserPreview: ParserPreview
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

export function uploadRequirementCopy(inputType: ImportInputType) {
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

function requiredFieldsPreviewLabel(parserPreview: ParserPreview) {
  const fields = parserPreview.requiredFieldsFound ?? []
  if (fields.includes("CVE column")) return "cve_id column found"
  return fields.join(", ")
}
