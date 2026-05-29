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
  uploads?: { input?: unknown } | null
  result?: Record<string, unknown> | null
}) {
  const upload = runInputUpload(run)
  const uploadFilename =
    stringValue(upload.original_filename) ??
    stringValue(upload.stored_filename) ??
    stringValue(upload.filename)
  return run.filename ?? uploadFilename ?? `${run.input_type} upload`
}

export function runInputUpload(run: {
  uploads?: { input?: unknown } | null
  result?: Record<string, unknown> | null
}) {
  return objectRecord(run.uploads?.input ?? run.result?.input_upload)
}

export function runAssetContextUpload(run: {
  uploads?: { asset_context?: unknown } | null
  result?: Record<string, unknown> | null
}) {
  return objectRecord(run.uploads?.asset_context ?? run.result?.asset_context_upload)
}

export function runVexUpload(run: {
  uploads?: { vex?: unknown } | null
  result?: Record<string, unknown> | null
}) {
  return objectRecord(run.uploads?.vex ?? run.result?.vex_upload)
}

export function runProviderSnapshotFile(run: {
  provider_snapshot?: { file?: string | null } | null
  result?: Record<string, unknown> | null
} | null | undefined) {
  if (!run) return null
  return (
    run.provider_snapshot?.file ??
    stringValue(run.result?.provider_snapshot_file)
  )
}

export function runProviderSnapshotHash(run: {
  provider_snapshot?: { hash?: string | null } | null
  result?: Record<string, unknown> | null
} | null | undefined) {
  if (!run) return null
  return (
    run.provider_snapshot?.hash ??
    stringValue(run.result?.provider_snapshot_hash)
  )
}

export function runLockedProviderData(run: {
  provider_snapshot?: { locked?: boolean | null } | null
  result?: Record<string, unknown> | null
} | null | undefined) {
  if (!run) return undefined
  if (typeof run.provider_snapshot?.locked === "boolean") {
    return run.provider_snapshot.locked
  }
  const value = run.result?.locked_provider_data
  return typeof value === "boolean" ? value : undefined
}

export function runResultRecord(
  run: { result?: Record<string, unknown> | null } | null | undefined,
  key: string,
) {
  return objectRecord(run?.result?.[key])
}

export function runResultString(
  run: { result?: Record<string, unknown> | null } | null | undefined,
  key: string,
) {
  return stringValue(run?.result?.[key])
}

export function runCount(
  run:
    | AnalysisRunPublic
    | AnalysisRunSummaryPublic
    | null
    | undefined,
  key:
    | "created_findings"
    | "updated_findings"
    | "ignored_lines"
    | "rows_read"
    | "occurrence_count"
    | "finding_count"
    | "kev_hits"
    | "suppressed_by_vex"
    | "attack_mapped_cves",
) {
  if (!run) return 0
  const direct = (run as Partial<Record<typeof key, unknown>>)[key]
  if (typeof direct === "number") return direct
  const countValue = "counts" in run ? run.counts?.[key] : undefined
  if (typeof countValue === "number") return countValue
  const resultValue = run.result?.[key]
  return typeof resultValue === "number" ? resultValue : 0
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
      summary?.diagnostics,
      run?.diagnostics,
      summary?.workflow?.diagnostics,
      run?.workflow?.diagnostics,
      summary?.workflow?.error_details,
      run?.workflow?.error_details,
    )
  if (typedMessage) return typedMessage
  return "No failure detail available."
}

function failureMessage(...failures: unknown[]) {
  for (const failure of failures) {
    const message = diagnosticMessage(failure)
    if (message) return message
  }
  return null
}

function diagnosticMessage(value: unknown): string | null {
  const record = objectRecord(value)
  const directMessage = stringValue(record.message)?.trim()
  if (directMessage) return directMessage

  const analysisError = objectRecord(record.analysis_error)
  const analysisMessage = stringValue(analysisError.message)?.trim()
  if (analysisMessage) return analysisMessage

  const parseErrors = Array.isArray(record.parse_errors)
    ? record.parse_errors
    : []
  for (const parseError of parseErrors) {
    const parseMessage = stringValue(objectRecord(parseError).message)?.trim()
    if (parseMessage) return parseMessage
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
