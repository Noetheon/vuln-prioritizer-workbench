import {
  fileMatchesAcceptedExtension,
  getImportFormat,
  isImportInputType,
} from "./import-format-catalog.ts"
import type {
  ImportReadinessCheck,
  ParserPreview,
} from "./import-format-types.ts"

export function buildImportReadinessChecks({
  evidenceFile,
  inputType,
  parserPreview,
  projectId,
  providerAvailable,
}: {
  evidenceFile: File | null
  inputType: string | null | undefined
  parserPreview: ParserPreview
  projectId: string
  providerAvailable: boolean
}): ImportReadinessCheck[] {
  const hasInputType = isImportInputType(inputType)
  const hasFile = Boolean(evidenceFile)
  const fileTypeOk = hasFile && hasInputType && fileMatchesAcceptedExtension(evidenceFile, inputType)
  const parserPending =
    parserPreview.state === "not-started" || parserPreview.state === "checking"
  const parserBlocking = parserPreview.state === "error"

  return [
    {
      id: "project",
      label: "Project selected",
      status: projectId ? "passed" : "missing",
      message: projectId ? "Project is selected." : "Select a project.",
      targetStep: 1,
    },
    {
      id: "input-type",
      label: "Input type selected",
      status: hasInputType ? "passed" : "missing",
      message: hasInputType ? getImportFormat(inputType)?.label : "Select an input type.",
      targetStep: 1,
    },
    {
      id: "evidence-file",
      label: "Evidence file uploaded",
      status: hasFile ? "passed" : "missing",
      message: hasFile ? evidenceFile?.name : "Choose an evidence file.",
      targetStep: 2,
    },
    {
      id: "file-type",
      label: "File type check",
      status: !hasFile ? "pending" : fileTypeOk ? "passed" : "error",
      message: !hasFile
        ? "Waiting for evidence file."
        : fileTypeOk
          ? "File extension matches the selected input type."
          : "This file does not match the selected input type.",
      targetStep: 2,
    },
    {
      id: "parser-preview",
      label: "Parser preview",
      status: !hasFile
        ? "pending"
        : parserPending
          ? "pending"
          : parserBlocking
            ? "error"
            : parserPreview.state === "warning"
              ? "warning"
              : "passed",
      message:
        parserPreview.errors[0] ??
        parserPreview.warnings[0] ??
        "Full parser results will be available after import.",
      targetStep: 2,
    },
    {
      id: "provider-data",
      label: "Provider data available",
      status: providerAvailable ? "passed" : "warning",
      message: providerAvailable
        ? "Current provider data is available."
        : "Provider data is unavailable or still loading.",
      targetStep: 3,
    },
    {
      id: "asset-context",
      label: "Asset context",
      status: "optional",
      message: "Not selected optional.",
      targetStep: 3,
    },
    {
      id: "vex",
      label: "VEX overlay",
      status: "optional",
      message: "Not selected optional.",
      targetStep: 3,
    },
    {
      id: "attack-context",
      label: "ATT&CK context",
      status: "optional",
      message: "Reviewed defensive context only.",
      targetStep: 3,
    },
  ]
}

export function readinessBlocksImport(checks: readonly ImportReadinessCheck[]) {
  return checks.some(
    (check) =>
      check.status === "missing" ||
      check.status === "error" ||
      (["file-type", "parser-preview", "asset-context", "vex"].includes(check.id) &&
        check.status === "pending"),
  )
}
