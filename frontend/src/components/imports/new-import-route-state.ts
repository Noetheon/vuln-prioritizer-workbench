import {
  readinessBlocksImport,
  type ImportReadinessCheck,
  type ParserPreview,
} from "../../lib/import-format-metadata.ts"
import type { ImportsWorkbenchProps } from "./imports-workbench-model"

export type StepId = 1 | 2 | 3 | 4

export type OptionalContextValidationState = {
  fileKey: string
  message: string
  status: "checking" | "passed" | "error"
}

export const stepLabels: Array<{
  id: StepId
  label: string
  description: string
}> = [
  { id: 1, label: "Choose source", description: "Project and input type" },
  { id: 2, label: "Upload file", description: "Main evidence file" },
  { id: 3, label: "Add context", description: "Optional local context" },
  { id: 4, label: "Review import", description: "Readiness and submit" },
]

export function disabledReasonForStep({
  canStartImport,
  evidenceFile,
  importLoading,
  inputType,
  parserPreview,
  selectedProjectId,
  step,
}: {
  canStartImport: boolean
  evidenceFile: File | null
  importLoading: boolean
  inputType: string
  parserPreview: ParserPreview
  selectedProjectId: string
  step: StepId
}) {
  if (importLoading) return "Import is running."
  if (step === 1) {
    if (!selectedProjectId) return "Select a project to continue."
    if (!inputType) return "Select an input type to continue."
    return ""
  }
  if (step === 2) {
    if (!evidenceFile) return "Continue is unavailable until an evidence file is selected."
    if (parserPreview.state === "not-started") return "File check has not started yet."
    if (parserPreview.state === "checking") return "File check is still running."
    if (parserPreview.state === "error") {
      return parserPreview.errors[0] ?? "Fix the file before continuing."
    }
    return ""
  }
  if (step === 3) {
    if (!canStartImport) return "Resolve optional context checks before continuing."
    return ""
  }
  if (!canStartImport) return "Fix blocking readiness items before starting import."
  return ""
}

export function optionalContextReadiness({
  assetContextFile,
  assetContextValidation,
  vexFile,
  vexValidation,
}: Pick<
  ImportsWorkbenchProps["importWizard"],
  "assetContextFile" | "vexFile"
> & {
  assetContextValidation?: OptionalContextValidationState | null
  vexValidation?: OptionalContextValidationState | null
}): Partial<Record<ImportReadinessCheck["id"], ImportReadinessCheck>> {
  return {
    "asset-context": optionalFileReadiness({
      file: assetContextFile,
      id: "asset-context",
      label: "Asset context",
      validation: assetContextValidation,
      validExtensions: [".csv"],
    }),
    vex: optionalFileReadiness({
      file: vexFile,
      id: "vex",
      label: "VEX overlay",
      validation: vexValidation,
      validExtensions: [".json"],
    }),
  }
}

export function readinessCopyForStep(
  step: StepId,
  readiness: readonly ImportReadinessCheck[],
  importLoading = false,
) {
  if (importLoading) return "Importing evidence"
  const blocking = readiness.find(
    (check) => check.status === "missing" || check.status === "error",
  )
  const projectMissing = checkHasStatus(readiness, "project", "missing")
  const inputMissing = checkHasStatus(readiness, "input-type", "missing")
  const evidenceMissing = checkHasStatus(readiness, "evidence-file", "missing")
  const parserPending = checkHasStatus(readiness, "parser-preview", "pending")

  if (step === 1) {
    if (projectMissing) return "Select a project"
    if (inputMissing) return "Needs input type"
    return "Continue to upload"
  }
  if (step === 2) {
    if (evidenceMissing) return "Needs evidence file"
    if (parserPending) return "Checking file"
    if (blocking) return "Needs attention"
    return "Can continue"
  }
  if (step === 3) {
    if (blocking) return "Needs attention"
    return "Can continue"
  }
  return blocking || readinessBlocksImport(readiness)
    ? "Needs attention"
    : "Ready to import"
}

export function readinessToneForStep(
  step: StepId,
  readiness: readonly ImportReadinessCheck[],
) {
  if (step === 4 && !readinessBlocksImport(readiness)) return "success" as const
  if (
    readiness.some(
      (check) => check.status === "missing" || check.status === "error",
    )
  ) {
    return "critical" as const
  }
  if (readiness.some((check) => check.status === "warning")) {
    return "warning" as const
  }
  return "neutral" as const
}

export function checkPassed(
  readiness: readonly ImportReadinessCheck[],
  id: ImportReadinessCheck["id"],
) {
  return readiness.find((check) => check.id === id)?.status === "passed"
}

export function checkHasStatus(
  readiness: readonly ImportReadinessCheck[],
  id: ImportReadinessCheck["id"],
  status: ImportReadinessCheck["status"],
) {
  return readiness.find((check) => check.id === id)?.status === status
}

export function blockedStepReason(
  stepId: StepId,
  canReachStep2: boolean,
  canReachStep3: boolean,
) {
  if (stepId === 2 && !canReachStep2) return "Select project and input type first."
  if ((stepId === 3 || stepId === 4) && !canReachStep3) {
    return "Upload a valid evidence file first."
  }
  return ""
}

function optionalFileReadiness({
  file,
  id,
  label,
  validation,
  validExtensions,
}: {
  file: File | null
  id: ImportReadinessCheck["id"]
  label: string
  validation?: OptionalContextValidationState | null
  validExtensions: string[]
}): ImportReadinessCheck {
  if (!file) {
    return {
      id,
      label,
      status: "optional",
      message: "Not selected optional.",
      targetStep: 3,
    }
  }
  const lowerName = file.name.toLowerCase()
  const extensionOk = validExtensions.some((extension) =>
    lowerName.endsWith(extension),
  )
  if (!extensionOk) {
    return {
      id,
      label,
      status: "error",
      message: `Use a ${validExtensions.join(" or ")} file for ${label.toLowerCase()}.`,
      targetStep: 3,
    }
  }
  if (validation?.fileKey === fileKey(file) && validation.status === "checking") {
    return {
      id,
      label,
      status: "pending",
      message: validation.message,
      targetStep: 3,
    }
  }
  if (validation?.fileKey === fileKey(file) && validation.status === "error") {
    return {
      id,
      label,
      status: "error",
      message: validation.message,
      targetStep: 3,
    }
  }
  return {
    id,
    label,
    status: "passed",
    message: validation?.fileKey === fileKey(file) ? validation.message : file.name,
    targetStep: 3,
  }
}

export function fileKey(file: File) {
  return `${file.name}:${file.size}:${file.lastModified}`
}

export async function validateAssetContextCsvFile(
  file: File,
): Promise<OptionalContextValidationState> {
  const key = fileKey(file)
  if (!file.name.toLowerCase().endsWith(".csv")) {
    return {
      fileKey: key,
      message: "Use a .csv file for asset context.",
      status: "error",
    }
  }
  const headerLine = (await file.text()).split(/\r?\n/, 1)[0] ?? ""
  const hasHeader = headerLine
    .split(",")
    .some((header) => header.trim().length > 0)
  return hasHeader
    ? {
        fileKey: key,
        message: "Asset context CSV header detected.",
        status: "passed",
      }
    : {
        fileKey: key,
        message: "Asset context CSV requires a non-empty header row.",
        status: "error",
      }
}

export async function validateVexJsonFile(
  file: File,
): Promise<OptionalContextValidationState> {
  const key = fileKey(file)
  if (!file.name.toLowerCase().endsWith(".json")) {
    return {
      fileKey: key,
      message: "Use a .json file for VEX overlay.",
      status: "error",
    }
  }
  try {
    JSON.parse(await file.text())
    return {
      fileKey: key,
      message: "VEX overlay JSON parsed.",
      status: "passed",
    }
  } catch {
    return {
      fileKey: key,
      message: "Invalid VEX overlay JSON.",
      status: "error",
    }
  }
}
