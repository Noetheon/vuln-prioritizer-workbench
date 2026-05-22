import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ImportParseErrorPublic,
  ProjectPublic,
  ProviderStatusPublic,
} from "@/api-client"
import type { VpwBadgeTone } from "@/components/vpw"
import {
  fileMatchesAcceptedExtension,
  fileSizeLabel as importFileSizeLabel,
  getImportFormat,
  type ImportInputType,
} from "../../lib/import-format-metadata.ts"
import type { FormEventHandler } from "react"
import { objectRecord, stringValue } from "./imports-workbench-records.ts"

export { formatDateTime } from "../../lib/date-format.ts"
export { importRunTimelineItems } from "./import-run-timeline-model.ts"
export { objectRecord, stringValue } from "./imports-workbench-records.ts"

export type SupportedImportFormat = {
  label: string
  value: ImportInputType
  accept: string
  detail: string
}

export type ImportWizardStateLike = {
  attackMappingFile?: string
  attackSource?: string
  attackTechniqueMetadataFile?: string
  assetContextFile: File | null
  file: File | null
  inputType: ImportInputType | ""
  lockedProviderData?: boolean
  providerSnapshotFile?: string
  vexFile: File | null
}

export type ImportsWorkbenchProps = {
  view?: "home" | "new" | "run" | "formats"
  importError: string
  failedImportRunId: string
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
  onUseDemoProviderSnapshot: () => void
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
  const metadata = getImportFormat(value)
  if (metadata) return metadata.minimumFields.join(", ")
  return "Supported Workbench import fields"
}

export function formatDisplayType(value: string) {
  return value.replaceAll("-", " ")
}

export function fileSizeLabel(file: File | null | undefined) {
  return importFileSizeLabel(file)
}

export function selectedFormat(
  formats: readonly SupportedImportFormat[],
  inputType: string,
) {
  return formats.find((format) => format.value === inputType)
}

export function optionalContextLabels(wizard: ImportWizardStateLike) {
  const labels: string[] = []
  if (wizard.assetContextFile) labels.push("Asset context CSV")
  if (wizard.vexFile) labels.push("VEX sidecar")
  if (wizard.attackSource && wizard.attackSource !== "none") {
    labels.push("Reviewed ATT&CK mapping")
  }
  return labels
}

export function hasOptionalContext(wizard: ImportWizardStateLike) {
  return optionalContextLabels(wizard).length > 0
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

export function importSubmitDisabled({
  importLoading,
  projectListLoading,
  projectCount,
  selectedProjectId,
  wizard,
}: {
  importLoading: boolean
  projectListLoading: boolean
  projectCount: number
  selectedProjectId: string
  wizard: ImportWizardStateLike
}) {
  return (
    importLoading ||
    projectListLoading ||
    projectCount === 0 ||
    !selectedProjectId ||
    !wizard.inputType ||
    !wizard.file ||
    !fileMatchesAcceptedExtension(wizard.file, wizard.inputType)
  )
}
