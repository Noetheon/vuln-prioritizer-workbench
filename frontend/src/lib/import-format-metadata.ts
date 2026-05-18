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

export const FORMAT_CATEGORY_LABELS: Record<SupportedFormatCategory, string> = {
  simple: "Simple inputs",
  scanner: "Scanner exports",
  sbom: "SBOM / dependency data",
  network: "Network scanner exports",
}

export const SUPPORTED_IMPORT_FORMATS: readonly SupportedFormat[] = [
  {
    inputType: "cve-list",
    label: "CVE list",
    category: "simple",
    categoryLabel: FORMAT_CATEGORY_LABELS.simple,
    extensions: [".txt", ".csv"],
    acceptedMimeTypes: ["text/plain", "text/csv"],
    bestFor: "Quick lists of already-known CVEs.",
    expectedShape: "Plain text or CSV with one CVE identifier per line.",
    minimumFields: ["One CVE identifier per line or a CVE column"],
    optionalFields: [],
    contextSupport: "cve-only",
    exampleSnippet: "CVE-2024-3094\nCVE-2023-4863",
    notes: ["Use this for quick supplied CVE lists without asset context."],
    shortDescription: "Plain text or CSV with one CVE identifier per line.",
  },
  {
    inputType: "generic-occurrence-csv",
    label: "Generic occurrence CSV",
    category: "simple",
    categoryLabel: FORMAT_CATEGORY_LABELS.simple,
    extensions: [".csv"],
    acceptedMimeTypes: ["text/csv"],
    bestFor: "Manual vulnerability backlog or occurrence lists.",
    expectedShape: "CSV with CVE identifiers and optional asset or component context.",
    minimumFields: ["cve_id or equivalent supported CVE field"],
    optionalFields: [
      "component_name",
      "component_version",
      "purl",
      "owner",
      "service",
      "environment",
      "fix_version",
    ],
    contextSupport: "asset-context-capable",
    exampleSnippet: "cve_id,component_name,component_version,owner,service\nCVE-2024-3094,xz,5.6.0,platform,payments",
    notes: ["Asset context can improve prioritization and explanations."],
    shortDescription: "CSV with CVE identifiers and optional asset or component context.",
  },
  {
    inputType: "trivy-json",
    label: "Trivy JSON",
    category: "scanner",
    categoryLabel: FORMAT_CATEGORY_LABELS.scanner,
    extensions: [".json"],
    acceptedMimeTypes: ["application/json"],
    bestFor: "Container and filesystem exports from Trivy.",
    expectedShape: "Trivy vulnerability report JSON.",
    minimumFields: ["Results[].Vulnerabilities[]"],
    optionalFields: ["PkgName", "InstalledVersion", "FixedVersion", "Severity"],
    contextSupport: "component-context",
    exampleSnippet: '{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-3094"}]}]}',
    notes: ["Use the JSON report exported by Trivy."],
    shortDescription: "Trivy vulnerability export.",
  },
  {
    inputType: "grype-json",
    label: "Grype JSON",
    category: "scanner",
    categoryLabel: FORMAT_CATEGORY_LABELS.scanner,
    extensions: [".json"],
    acceptedMimeTypes: ["application/json"],
    bestFor: "Container and SBOM exports from Grype.",
    expectedShape: "Grype vulnerability report JSON.",
    minimumFields: ["matches[] vulnerability data"],
    optionalFields: ["artifact", "fix", "matchDetails"],
    contextSupport: "component-context",
    exampleSnippet: '{"matches":[{"vulnerability":{"id":"CVE-2024-3094"}}]}',
    notes: ["Use the JSON report exported by Grype."],
    shortDescription: "Grype vulnerability export.",
  },
  {
    inputType: "cyclonedx-json",
    label: "CycloneDX SBOM JSON",
    category: "sbom",
    categoryLabel: FORMAT_CATEGORY_LABELS.sbom,
    extensions: [".json"],
    acceptedMimeTypes: ["application/json"],
    bestFor: "Software inventory with vulnerability references.",
    expectedShape: "CycloneDX components plus vulnerability references.",
    minimumFields: ["components", "vulnerabilities"],
    optionalFields: ["bom-ref", "purl", "affects"],
    contextSupport: "component-vulnerability-context",
    exampleSnippet: '{"bomFormat":"CycloneDX","components":[],"vulnerabilities":[{"id":"CVE-2024-3094"}]}',
    notes: ["Plain SBOM-only BOM without vulnerabilities is not sufficient."],
    shortDescription: "CycloneDX SBOM plus vulnerabilities.",
  },
  {
    inputType: "spdx-json",
    label: "SPDX SBOM JSON",
    category: "sbom",
    categoryLabel: FORMAT_CATEGORY_LABELS.sbom,
    extensions: [".json"],
    acceptedMimeTypes: ["application/json"],
    bestFor: "SPDX package inventory with vulnerability references where supported.",
    expectedShape: "SPDX JSON package data.",
    minimumFields: ["packages"],
    optionalFields: ["externalRefs", "relationships"],
    contextSupport: "component-context",
    exampleSnippet: '{"spdxVersion":"SPDX-2.3","packages":[]}',
    notes: ["Package data is parsed locally from supplied SPDX JSON."],
    shortDescription: "SPDX JSON package data.",
  },
  {
    inputType: "dependency-check-json",
    label: "Dependency-Check JSON",
    category: "scanner",
    categoryLabel: FORMAT_CATEGORY_LABELS.scanner,
    extensions: [".json"],
    acceptedMimeTypes: ["application/json"],
    bestFor: "OWASP Dependency-Check output.",
    expectedShape: "OWASP Dependency-Check JSON report.",
    minimumFields: ["dependencies[].vulnerabilities[]"],
    optionalFields: ["packages", "evidenceCollected", "severity"],
    contextSupport: "component-context",
    exampleSnippet: '{"dependencies":[{"vulnerabilities":[{"name":"CVE-2024-3094"}]}]}',
    notes: ["Use the JSON report exported by OWASP Dependency-Check."],
    shortDescription: "OWASP Dependency-Check JSON report.",
  },
  {
    inputType: "github-alerts-json",
    label: "GitHub alerts JSON",
    category: "scanner",
    categoryLabel: FORMAT_CATEGORY_LABELS.scanner,
    extensions: [".json"],
    acceptedMimeTypes: ["application/json"],
    bestFor: "Pinned GitHub security or dependency alert evidence.",
    expectedShape: "Pinned GitHub alert export shape.",
    minimumFields: ["alert vulnerability records"],
    optionalFields: ["dependency", "security_vulnerability", "security_advisory"],
    contextSupport: "component-context",
    exampleSnippet: '[{"security_vulnerability":{"vulnerable_version_range":"< 1.0.0"},"security_advisory":{"cve_id":"CVE-2024-3094"}}]',
    notes: ["Use the pinned JSON export shape supported by the backend."],
    shortDescription: "Pinned GitHub alert JSON export shape.",
  },
  {
    inputType: "nessus-xml",
    label: "Nessus XML",
    category: "network",
    categoryLabel: FORMAT_CATEGORY_LABELS.network,
    extensions: [".nessus", ".xml"],
    acceptedMimeTypes: ["application/xml", "text/xml"],
    bestFor: "Network tool export evidence supplied as local XML.",
    expectedShape: "Nessus export with ReportHost / ReportItem CVE data.",
    minimumFields: ["ReportHost", "ReportItem CVE data"],
    optionalFields: ["plugin_output", "severity", "solution"],
    contextSupport: "partial-occurrence-context",
    exampleSnippet: "<NessusClientData_v2><Report><ReportHost name=\"host\"><ReportItem><cve>CVE-2024-3094</cve></ReportItem></ReportHost></Report></NessusClientData_v2>",
    notes: ["Parsed locally from supplied exports; the Workbench does not scan networks."],
    shortDescription: "Nessus XML export parsed locally.",
  },
  {
    inputType: "openvas-xml",
    label: "OpenVAS XML",
    category: "network",
    categoryLabel: FORMAT_CATEGORY_LABELS.network,
    extensions: [".xml"],
    acceptedMimeTypes: ["application/xml", "text/xml"],
    bestFor: "OpenVAS-style result evidence supplied as local XML.",
    expectedShape: "OpenVAS result CVE data.",
    minimumFields: ["result CVE data"],
    optionalFields: ["host", "port", "threat", "description"],
    contextSupport: "partial-occurrence-context",
    exampleSnippet: "<report><results><result><nvt><cve>CVE-2024-3094</cve></nvt></result></results></report>",
    notes: ["Parsed locally from supplied exports; the Workbench does not scan networks."],
    shortDescription: "OpenVAS XML export parsed locally.",
  },
] as const

export const SUPPORTED_IMPORT_INPUT_TYPES = SUPPORTED_IMPORT_FORMATS.map(
  (format) => format.inputType,
)

export function isImportInputType(value: string | null | undefined): value is ImportInputType {
  return SUPPORTED_IMPORT_INPUT_TYPES.includes(value as ImportInputType)
}

export function getImportFormat(
  inputType: string | null | undefined,
): SupportedFormat | undefined {
  return SUPPORTED_IMPORT_FORMATS.find((format) => format.inputType === inputType)
}

export function getAcceptedExtensions(inputType: string | null | undefined) {
  return getImportFormat(inputType)?.extensions ?? []
}

export function getAcceptedMimeTypes(inputType: string | null | undefined) {
  return getImportFormat(inputType)?.acceptedMimeTypes ?? []
}

export function acceptedFileInputValue(inputType: string | null | undefined) {
  const format = getImportFormat(inputType)
  if (!format) return ""
  return [...format.extensions, ...format.acceptedMimeTypes].join(",")
}

export function fileSizeLabel(file: File | null | undefined) {
  if (!file) return "No file selected"
  if (file.size < 1024) return `${file.size} B`
  if (file.size < 1024 * 1024) return `${(file.size / 1024).toFixed(1)} KB`
  return `${(file.size / (1024 * 1024)).toFixed(1)} MB`
}

export function fileMatchesAcceptedExtension(
  file: File | null | undefined,
  inputType: string | null | undefined,
) {
  if (!file || !isImportInputType(inputType)) return false
  const lowerName = file.name.toLowerCase()
  const extensions = getAcceptedExtensions(inputType)
  return extensions.some((extension) => lowerName.endsWith(extension))
}

export function initialParserPreview(): ParserPreview {
  return {
    state: "not-started",
    warnings: [],
    errors: [],
  }
}

export async function buildParserPreview(
  file: File | null,
  inputType: string | null | undefined,
): Promise<ParserPreview> {
  if (!file || !isImportInputType(inputType)) {
    return initialParserPreview()
  }

  const base: ParserPreview = {
    state: "passed",
    fileName: file.name,
    fileSizeBytes: file.size,
    contentType: file.type || undefined,
    warnings: [],
    errors: [],
  }

  if (!fileMatchesAcceptedExtension(file, inputType)) {
    return {
      ...base,
      state: "error",
      errors: ["Unsupported file type for the selected input type."],
    }
  }

  if (inputType === "cve-list") {
    const text = await file.text()
    const nonEmptyLines = text.split(/\r?\n/).filter((line) => line.trim())
    const cveMatches = text.match(/\bCVE-\d{4}-\d{4,}\b/gi) ?? []
    return {
      ...base,
      candidateRows: cveMatches.length,
      ignoredRows: Math.max(0, nonEmptyLines.length - cveMatches.length),
      requiredFieldsFound: cveMatches.length > 0 ? ["CVE identifier"] : [],
      missingRequiredFields: cveMatches.length > 0 ? [] : ["CVE identifier"],
      state: cveMatches.length > 0 ? "passed" : "error",
      warnings:
        nonEmptyLines.length > cveMatches.length
          ? ["Some non-empty lines do not look like CVE identifiers."]
          : [],
      errors: cveMatches.length > 0 ? [] : ["No CVE identifiers detected."],
    }
  }

  if (inputType === "generic-occurrence-csv") {
    const text = await file.text()
    const [headerLine = "", ...rows] = text.split(/\r?\n/)
    const headers = headerLine
      .split(",")
      .map((header) => header.trim().toLowerCase())
      .filter(Boolean)
    const hasCveHeader = headers.some((header) =>
      ["cve", "cve_id", "cveid", "vulnerability_id"].includes(header),
    )
    return {
      ...base,
      candidateRows: rows.filter((row) => row.trim()).length,
      requiredFieldsFound: hasCveHeader ? ["CVE column"] : [],
      missingRequiredFields: hasCveHeader ? [] : ["CVE column"],
      state: hasCveHeader ? "passed" : "error",
      errors: hasCveHeader ? [] : ["Missing required CSV header: cve_id."],
    }
  }

  if (inputType.endsWith("-json")) {
    try {
      JSON.parse(await file.text())
      return {
        ...base,
        warnings: ["Full parser results will be available after import."],
      }
    } catch {
      return {
        ...base,
        state: "error",
        errors: ["Invalid JSON."],
      }
    }
  }

  return {
    ...base,
    warnings: ["File selected. Full parser validation will run when the import starts."],
  }
}

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
