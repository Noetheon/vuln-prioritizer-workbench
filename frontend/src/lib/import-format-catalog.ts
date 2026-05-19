import type {
  ImportInputType,
  SupportedFormat,
  SupportedFormatCategory,
} from "./import-format-types.ts"

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
    exampleSnippet:
      "cve_id,component_name,component_version,owner,service\nCVE-2024-3094,xz,5.6.0,platform,payments",
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
    exampleSnippet:
      '{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-3094"}]}]}',
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
    exampleSnippet:
      '{"bomFormat":"CycloneDX","components":[],"vulnerabilities":[{"id":"CVE-2024-3094"}]}',
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
    exampleSnippet:
      '{"dependencies":[{"vulnerabilities":[{"name":"CVE-2024-3094"}]}]}',
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
    exampleSnippet:
      '[{"security_vulnerability":{"vulnerable_version_range":"< 1.0.0"},"security_advisory":{"cve_id":"CVE-2024-3094"}}]',
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
    exampleSnippet:
      '<NessusClientData_v2><Report><ReportHost name="host"><ReportItem><cve>CVE-2024-3094</cve></ReportItem></ReportHost></Report></NessusClientData_v2>',
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
    exampleSnippet:
      "<report><results><result><nvt><cve>CVE-2024-3094</cve></nvt></result></results></report>",
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
