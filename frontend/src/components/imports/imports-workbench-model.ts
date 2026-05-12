import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ImportParseErrorPublic,
  ProjectPublic,
  ProviderStatusPublic,
} from "@/api-client"
import type { VpwBadgeTone } from "@/components/vpw"
import type { FormEventHandler } from "react"

export type SupportedImportFormat = {
  label: string
  value: string
  accept: string
  detail: string
}

export type ImportWizardStateLike = {
  attackMappingFile?: string
  attackSource?: string
  attackTechniqueMetadataFile?: string
  assetContextFile: File | null
  file: File | null
  inputType: string
  lockedProviderData?: boolean
  providerSnapshotFile?: string
  vexFile: File | null
}

export type ImportsWorkbenchProps = {
  importError: string
  importLoading: boolean
  importParseErrors: ImportParseErrorPublic[]
  importRun: AnalysisRunPublic | null
  importRunSummary: AnalysisRunSummaryPublic | null
  importWizard: ImportWizardStateLike
  onAssetContextFileChange: (file: File | null) => void
  onFileChange: (file: File | null) => void
  onInputTypeChange: (value: string) => void
  onLockedProviderDataChange: (value: boolean) => void
  onProviderSnapshotFileChange: (value: string) => void
  onProjectChange: (projectId: string) => void
  onRefreshRuns: () => void
  onSelectRun: (runId: string) => void
  onSubmit: FormEventHandler<HTMLFormElement>
  onAttackMappingFileChange: (value: string) => void
  onAttackSourceChange: (value: string) => void
  onAttackTechniqueMetadataFileChange: (value: string) => void
  onVexFileChange: (file: File | null) => void
  projectListLoading: boolean
  projectListError: string
  projectRuns: AnalysisRunPublic[]
  projects: ProjectPublic[]
  providerStatus: ProviderStatusPublic | null
  runDetailError: string
  runDetailLoading: boolean
  runsError: string
  runsLoading: boolean
  selectedProject: ProjectPublic | null
  selectedProjectId: string
  selectedRun: AnalysisRunPublic | null
  selectedRunId: string
  selectedRunSummary: AnalysisRunSummaryPublic | null
  supportedFormats: readonly SupportedImportFormat[]
}

export function formatDateTime(value: string | null | undefined) {
  if (!value) return "Not recorded"
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return "Not recorded"
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date)
}

export function objectRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {}
}

export function stringValue(value: unknown) {
  return typeof value === "string" && value.trim() ? value : null
}

export function runFileLabel(run: {
  filename?: string | null
  input_type: string
  input_upload?: Record<string, unknown>
  summary_json?: Record<string, unknown>
}) {
  const upload = objectRecord(
    run.input_upload ?? run.summary_json?.input_upload,
  )
  const uploadFilename = stringValue(upload.filename)
  return run.filename ?? uploadFilename ?? `${run.input_type} upload`
}

export function metadataRows(value: unknown) {
  return Object.entries(objectRecord(value)).filter(
    ([key, entryValue]) =>
      !key.toLowerCase().includes("path") &&
      entryValue !== null &&
      entryValue !== undefined &&
      typeof entryValue !== "object",
  )
}

export function jsonPreview(value: unknown) {
  const record = objectRecord(value)
  return Object.keys(record).length > 0
    ? JSON.stringify(record, null, 2)
    : "No error JSON recorded."
}

export function failedRunCause(
  run: AnalysisRunPublic | null,
  summary: AnalysisRunSummaryPublic | null,
) {
  if (!run && !summary) return "No failure detail available."
  const errorJson = objectRecord(summary?.error_json ?? run?.error_json)
  const analysisError = objectRecord(errorJson.analysis_error)
  return (
    run?.error_message ??
    stringValue(errorJson.message) ??
    stringValue(errorJson.error) ??
    stringValue(errorJson.last_error) ??
    stringValue(analysisError.message) ??
    "No failure detail available."
  )
}

export function runTone(status: AnalysisRunPublic["status"]): VpwBadgeTone {
  if (status === "succeeded" || status === "completed") return "success"
  if (status === "failed" || status === "cancelled") return "critical"
  if (status === "completed_with_errors") return "warning"
  return "neutral"
}

export function formatExpectedFields(value: string) {
  if (value === "cve-list") return "One CVE per line"
  if (value === "generic-occurrence-csv") {
    return "cve_id plus optional asset/component columns"
  }
  if (value === "trivy-json") return "Trivy Results[].Vulnerabilities"
  if (value === "grype-json") return "Grype matches[] vulnerability data"
  if (value === "cyclonedx-json") return "CycloneDX components/vulnerabilities"
  if (value === "spdx-json") return "SPDX packages/vulnerability references"
  if (value === "dependency-check-json") return "Dependency-Check dependencies[].vulnerabilities"
  if (value === "github-alerts-json") return "GitHub alert vulnerability records"
  if (value === "nessus-xml") return "Nessus ReportHost/ReportItem CVE data"
  if (value === "openvas-xml") return "OpenVAS result CVE data"
  return "Supported Workbench import fields"
}

export function formatDisplayType(value: string) {
  return value.replaceAll("-", " ")
}

export function selectedFormat(
  formats: readonly SupportedImportFormat[],
  inputType: string,
) {
  return formats.find((format) => format.value === inputType) ?? formats[0]
}

export function uploadProgress(wizard: ImportWizardStateLike) {
  let value = 20
  if (wizard.inputType) value += 20
  if (wizard.file) value += 30
  if (wizard.assetContextFile) value += 15
  if (wizard.vexFile) value += 15
  if (wizard.providerSnapshotFile || (wizard.attackSource && wizard.attackSource !== "none")) {
    value += 5
  }
  return Math.min(value, 100)
}
