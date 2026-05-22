import {
  FileArchive,
  FileJson,
  FileText,
  GitBranch,
  type LucideIcon,
  Table2,
} from "lucide-react"

import type {
  AssetExposure,
  FindingPriority,
  FindingStatus,
  FindingsReadProjectFindingsData,
  ImportsService,
} from "../api-client"
import {
  acceptedFileInputValue,
  SUPPORTED_IMPORT_FORMATS,
  type ImportInputType,
} from "./import-format-metadata.ts"

export type ProjectFormState = {
  name: string
  description: string
}

export const emptyProjectForm: ProjectFormState = {
  name: "",
  description: "",
}

export const workbenchImportFormats = SUPPORTED_IMPORT_FORMATS.map((format) => ({
  label: format.label,
  value: format.inputType,
  accept: acceptedFileInputValue(format.inputType),
  detail: format.shortDescription,
}))

export type ImportFormat = ImportInputType
export type AttackImportSource = "none" | "ctid-json" | "local-curated"

export const attackImportSourceOptions: Array<{
  detail: string
  label: string
  value: AttackImportSource
}> = [
  {
    detail: "Do not enrich this import with ATT&CK mappings.",
    label: "No ATT&CK mapping",
    value: "none",
  },
  {
    detail: "Use a reviewed CTID JSON mapping file from the managed artifact directory.",
    label: "CTID JSON",
    value: "ctid-json",
  },
  {
    detail: "Use a reviewed local curated mapping file from the managed artifact directory.",
    label: "Local curated",
    value: "local-curated",
  },
]

export type WorkbenchReportFormat =
  | "markdown"
  | "html"
  | "json"
  | "csv"
  | "zip"
  | "attack-navigator"
  | "sarif"

export const reportActionCards: Array<{
  actionLabel: string
  detail: string
  format: string
  icon: LucideIcon
  reportFormat: WorkbenchReportFormat
  title: string
}> = [
  {
    actionLabel: "Generate Markdown",
    detail:
      "Technical report for analyst handoff, pull requests, and audit notes.",
    format: "Markdown",
    icon: FileText,
    reportFormat: "markdown",
    title: "Technical Markdown Report",
  },
  {
    actionLabel: "Generate executive HTML",
    detail:
      "Executive browser report with priority summary, evidence links, and safe rendering.",
    format: "HTML",
    icon: FileArchive,
    reportFormat: "html",
    title: "Executive HTML Report",
  },
  {
    actionLabel: "Export analysis JSON",
    detail:
      "Machine-readable findings and analysis data for automation and downstream systems.",
    format: "JSON",
    icon: FileJson,
    reportFormat: "json",
    title: "JSON Findings Export",
  },
  {
    actionLabel: "Export CSV findings",
    detail:
      "Spreadsheet-friendly findings table for triage, filtering, and stakeholder review.",
    format: "CSV",
    icon: Table2,
    reportFormat: "csv",
    title: "CSV Findings Export",
  },
  {
    actionLabel: "Export Navigator",
    detail:
      "Defensive ATT&CK Navigator JSON when mapped techniques are available.",
    format: "Navigator JSON",
    icon: GitBranch,
    reportFormat: "attack-navigator",
    title: "ATT&CK Navigator Layer",
  },
  {
    actionLabel: "Export SARIF",
    detail:
      "SARIF 2.1.0 results for GitHub code scanning and CI security evidence workflows.",
    format: "SARIF",
    icon: FileJson,
    reportFormat: "sarif",
    title: "SARIF Export",
  },
  {
    actionLabel: "Build evidence ZIP",
    detail:
      "ZIP package with reports, manifest, source artifacts, and SHA256 checksums.",
    format: "Evidence ZIP",
    icon: FileArchive,
    reportFormat: "zip",
    title: "Evidence ZIP Bundle",
  },
]

export type ImportWizardState = {
  attackMappingFile: string
  attackSource: AttackImportSource
  attackTechniqueMetadataFile: string
  assetContextFile: File | null
  file: File | null
  inputType: ImportFormat | ""
  lockedProviderData: boolean
  providerSnapshotFile: string
  vexFile: File | null
}

export const demoProviderSnapshotFile = "demo_provider_snapshot.json"

export const defaultImportWizardState: ImportWizardState = {
  attackMappingFile: "",
  attackSource: "none",
  attackTechniqueMetadataFile: "",
  assetContextFile: null,
  file: null,
  inputType: "",
  lockedProviderData: false,
  providerSnapshotFile: "",
  vexFile: null,
}

export function withDemoProviderSnapshot(
  state: ImportWizardState,
): ImportWizardState {
  return {
    ...state,
    lockedProviderData: true,
    providerSnapshotFile: demoProviderSnapshotFile,
  }
}

export type ImportUploadFormData = Parameters<
  typeof ImportsService.importProjectUpload
>[0]["bodyImportsImportProjectUpload"]

export type FindingsSort = NonNullable<FindingsReadProjectFindingsData["sort"]>
export type FindingsDirection = NonNullable<
  FindingsReadProjectFindingsData["direction"]
>

export type KevFilter = "" | "true" | "false"

export type FindingFilters = {
  cvssMax: string
  cvssMin: string
  epssMax: string
  epssMin: string
  exposure: "" | AssetExposure
  kev: KevFilter
  ownerService: string
  priority: "" | FindingPriority
  query: string
  status: "" | FindingStatus
}

export const defaultFindingFilters: FindingFilters = {
  cvssMax: "",
  cvssMin: "",
  epssMax: "",
  epssMin: "",
  exposure: "",
  kev: "",
  ownerService: "",
  priority: "",
  query: "",
  status: "",
}

export const findingPageSizes = [1, 10, 25, 50] as const

export type FindingDetailTab =
  | "decision"
  | "evidence"
  | "occurrences"
  | "ttp"
  | "history"
  | "governance"

export const findingPriorityOptions: FindingPriority[] = [
  "critical",
  "high",
  "medium",
  "low",
]

export const findingStatusOptions: FindingStatus[] = [
  "open",
  "in_review",
  "remediating",
  "fixed",
  "accepted",
  "suppressed",
]

export const findingExposureOptions: AssetExposure[] = [
  "internet-facing",
  "internal",
  "private",
  "unknown",
]

export const findingSortOptions: { label: string; value: FindingsSort }[] = [
  { label: "Operational", value: "operational" },
  { label: "Priority", value: "priority" },
  { label: "Score", value: "score" },
  { label: "CVE", value: "cve" },
  { label: "Status", value: "status" },
  { label: "EPSS", value: "epss" },
  { label: "CVSS", value: "cvss" },
  { label: "KEV", value: "kev" },
  { label: "Last Seen", value: "last_seen" },
]

export const evidenceTimeline = [
  "Provider snapshot locked",
  "Trivy import normalized",
  "Evidence bundle verified",
]
