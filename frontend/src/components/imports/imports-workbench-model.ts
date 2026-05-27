import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  AttackSourceCapabilityPublic,
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
  type SupportedFormat,
} from "../../lib/import-format-metadata.ts"
import type { FormEventHandler } from "react"
import { objectRecord, stringValue } from "./imports-workbench-records.ts"

export { formatDateTime } from "../../lib/date-format.ts"
export { importRunTimelineItems } from "./import-run-timeline-model.ts"
export { objectRecord, stringValue } from "./imports-workbench-records.ts"

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
  capabilitiesError: string
  capabilitiesLoading: boolean
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
  attackSources: readonly AttackSourceCapabilityPublic[]
  supportedFormats: readonly SupportedFormat[]
}

export function runFileLabel(run: {
  filename?: string | null
  input_type: string
  input_upload?: unknown
}) {
  const upload = objectRecord(run.input_upload)
  const uploadFilename =
    stringValue(upload.original_filename) ??
    stringValue(upload.stored_filename) ??
    stringValue(upload.filename)
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
  const typedMessage =
    run?.error_message ??
    failureMessage(
      summary?.analysis_error,
      summary?.asset_context_error,
      summary?.vex_error,
      summary?.background_error,
      summary?.workflow_error?.analysis_error,
      summary?.workflow_error?.asset_context_error,
      summary?.workflow_error?.vex_error,
      summary?.workflow_error?.background_error,
      run?.analysis_error,
      run?.asset_context_error,
      run?.vex_error,
      run?.background_error,
      run?.workflow_error?.analysis_error,
      run?.workflow_error?.asset_context_error,
      run?.workflow_error?.vex_error,
      run?.workflow_error?.background_error,
    )
  if (typedMessage) return typedMessage
  return "No failure detail available."
}

function failureMessage(
  ...failures: ({ message?: string | null } | null | undefined)[]
) {
  for (const failure of failures) {
    if (failure?.message?.trim()) return failure.message
  }
  return null
}

export function runTone(status: AnalysisRunPublic["status"]): VpwBadgeTone {
  if (status === "succeeded" || status === "completed") return "success"
  if (status === "failed" || status === "cancelled") return "critical"
  if (status === "completed_with_errors") return "warning"
  return "neutral"
}

export function formatExpectedFields(
  formats: readonly SupportedFormat[],
  value: string,
) {
  const metadata = getImportFormat(formats, value)
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
  formats: readonly SupportedFormat[],
  inputType: string,
) {
  return formats.find((format) => format.inputType === inputType)
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
  supportedFormats,
  projectCount,
  selectedProjectId,
  wizard,
}: {
  importLoading: boolean
  projectListLoading: boolean
  supportedFormats: readonly SupportedFormat[]
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
    !fileMatchesAcceptedExtension(supportedFormats, wizard.file, wizard.inputType)
  )
}
