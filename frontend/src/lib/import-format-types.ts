export type ImportInputType =
  | "cve-list"
  | "generic-occurrence-csv"
  | "trivy-json"
  | "grype-json"
  | "cyclonedx-json"
  | "spdx-json"
  | "dependency-check-json"
  | "github-alerts-json"
  | "nessus-xml"
  | "openvas-xml"

export type ProviderDataMode = "current" | "demo-snapshot" | "custom-snapshot"

export type SupportedFormatCategory =
  | "simple"
  | "scanner"
  | "sbom"
  | "network"

export type ContextSupport =
  | "cve-only"
  | "partial-occurrence-context"
  | "component-context"
  | "component-vulnerability-context"
  | "asset-context-capable"

export type SupportedFormat = {
  inputType: ImportInputType
  label: string
  category: SupportedFormatCategory
  categoryLabel: string
  extensions: string[]
  acceptedMimeTypes: string[]
  bestFor: string
  expectedShape: string
  minimumFields: string[]
  optionalFields: string[]
  contextSupport: ContextSupport
  exampleSnippet: string
  notes: string[]
  shortDescription: string
}

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
