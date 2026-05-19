import type { CSSProperties } from "react"
import type { ImportInputType } from "@/lib/import-format-metadata"
import { cn } from "@/lib/utils"
import {
  CveListGlyph,
  CsvOccurrenceGlyph,
  CycloneDxGlyph,
  DependencyCheckGlyph,
  GithubAlertsGlyph,
  GrypeGlyph,
  NessusGlyph,
  OpenVasGlyph,
  SpdxGlyph,
  TrivyGlyph,
} from "./NewImportSourceGlyphIcons"

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

export function ImportSourceMark({
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
      return <CveListGlyph />
    case "generic-occurrence-csv":
      return <CsvOccurrenceGlyph />
    case "trivy-json":
      return <TrivyGlyph />
    case "grype-json":
      return <GrypeGlyph />
    case "dependency-check-json":
      return <DependencyCheckGlyph />
    case "github-alerts-json":
      return <GithubAlertsGlyph />
    case "cyclonedx-json":
      return <CycloneDxGlyph />
    case "spdx-json":
      return <SpdxGlyph />
    case "nessus-xml":
      return <NessusGlyph />
    case "openvas-xml":
      return <OpenVasGlyph />
    default:
      return null
  }
}
