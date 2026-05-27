import type { ImportFormatCapabilityPublic } from "../api-client"

export type ImportInputType = ImportFormatCapabilityPublic["input_type"]
export type SupportedFormatCategory = ImportFormatCapabilityPublic["category"]
export type ContextSupport = ImportFormatCapabilityPublic["context_support"]

export type SupportedFormat = {
  acceptedMimeTypes: string[]
  bestFor: ImportFormatCapabilityPublic["best_for"]
  category: SupportedFormatCategory
  categoryLabel: ImportFormatCapabilityPublic["category_label"]
  contextSupport: ContextSupport
  exampleSnippet: ImportFormatCapabilityPublic["example_snippet"]
  expectedShape: ImportFormatCapabilityPublic["expected_shape"]
  extensions: string[]
  inputType: ImportInputType
  label: ImportFormatCapabilityPublic["label"]
  minimumFields: string[]
  notes: string[]
  optionalFields: string[]
  shortDescription: ImportFormatCapabilityPublic["short_description"]
}

export type ProviderDataMode = "current" | "demo-snapshot" | "custom-snapshot"

export type ImportDraft = {
  projectId: string | null
  inputType: ImportInputType | null
  evidenceFile: File | null
  assetContextFile: File | null
  vexFile: File | null
  attackMappingFile: File | null
  techniqueMetadataFile: File | null
  providerMode: ProviderDataMode
  providerSnapshotFileName: string | null
  lockProviderData: boolean
}

export type ReadinessStatus =
  | "passed"
  | "missing"
  | "warning"
  | "error"
  | "optional"
  | "pending"

export type ImportReadinessCheck = {
  id:
    | "project"
    | "input-type"
    | "evidence-file"
    | "file-type"
    | "parser-preview"
    | "provider-data"
    | "asset-context"
    | "vex"
    | "attack-context"
  label: string
  status: ReadinessStatus
  message?: string
  targetStep?: 1 | 2 | 3 | 4
}

export type ParserPreview = {
  state: "not-started" | "checking" | "passed" | "warning" | "error"
  detectedInputType?: ImportInputType
  fileName?: string
  fileSizeBytes?: number
  contentType?: string
  candidateRows?: number
  requiredFieldsFound?: string[]
  missingRequiredFields?: string[]
  ignoredRows?: number
  warnings: string[]
  errors: string[]
}
