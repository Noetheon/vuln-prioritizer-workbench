import {
  fileMatchesAcceptedExtension,
  isImportInputType,
} from "./import-format-catalog.ts"
import type {
  ParserPreview,
  SupportedFormat,
} from "./import-format-types.ts"

export function initialParserPreview(): ParserPreview {
  return {
    state: "not-started",
    warnings: [],
    errors: [],
  }
}

export async function buildParserPreview(
  formats: readonly SupportedFormat[],
  file: File | null,
  inputType: string | null | undefined,
  options: { sbomScanner?: "none" | "grype" } = {},
): Promise<ParserPreview> {
  if (!file || !isImportInputType(formats, inputType)) {
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

  if (!fileMatchesAcceptedExtension(formats, file, inputType)) {
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
    const hasCveHeader = headers.includes("cve_id")
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
      const document = JSON.parse(await file.text())
      if (
        ["cyclonedx-json", "spdx-json"].includes(inputType) &&
        document &&
        typeof document === "object" &&
        (!Array.isArray(document.vulnerabilities) ||
          document.vulnerabilities.length === 0)
      ) {
        return {
          ...base,
          state: options.sbomScanner === "grype" ? "passed" : "warning",
          warnings: [
            options.sbomScanner === "grype"
              ? "Inventory received. Vulnerability matches and assessment limitations will be available after the Grype scan."
              : "No vulnerability records are present. Enable Scan SBOM with Grype to assess this inventory, or upload a file with vulnerability records.",
          ],
        }
      }
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
