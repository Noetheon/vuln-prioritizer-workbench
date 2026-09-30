import {
  fileMatchesAcceptedExtension,
  getImportFormat,
  isImportInputType,
} from "./import-format-catalog.ts"
import type {
  ImportInputType,
  ParserPreview,
  SupportedFormat,
} from "./import-format-types.ts"

// Mirrors the importer: a value must be a whole CVE identifier.
const CVE_ID = /^CVE-\d{4}-\d{4,}$/i
const COMMENT_PREFIX = "#"
const CSV_DELIMITERS = [",", ";", "\t", "|"] as const
const LISTED_INVALID_LINES = 5

type CsvRecord = { cells: string[]; line: number }
type CveValue = { line: number; value: string }

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
    return cveListPreview(base, await file.text(), file.name)
  }

  if (inputType === "generic-occurrence-csv") {
    return occurrenceCsvPreview(base, await file.text())
  }

  if (inputType.endsWith("-json")) {
    let document: unknown
    try {
      document = JSON.parse(await file.text())
    } catch {
      return {
        ...base,
        state: "error",
        errors: ["Invalid JSON."],
      }
    }
    const detected = detectJsonInputType(document)
    if (detected && detected !== inputType && isImportInputType(formats, detected)) {
      const detectedLabel = getImportFormat(formats, detected)?.label ?? detected
      const selectedLabel = getImportFormat(formats, inputType)?.label ?? inputType
      return {
        ...base,
        detectedInputType: detected,
        state: "error",
        errors: [
          `This file looks like ${detectedLabel}, not ${selectedLabel}. Choose ${detectedLabel} as the input type.`,
        ],
      }
    }
    if (
      ["cyclonedx-json", "spdx-json"].includes(inputType) &&
      isRecord(document) &&
      (!Array.isArray(document.vulnerabilities) ||
        document.vulnerabilities.length === 0)
    ) {
      return {
        ...base,
        detectedInputType: detected ?? undefined,
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
      detectedInputType: detected ?? undefined,
      warnings: ["Full parser results will be available after import."],
    }
  }

  return {
    ...base,
    warnings: ["File selected. Full parser validation will run when the import starts."],
  }
}

/**
 * The JSON format a document is, by the same markers the importer uses to
 * detect it; null when none match.
 */
export function detectJsonInputType(document: unknown): ImportInputType | null {
  if (Array.isArray(document)) return "github-alerts-json"
  if (!isRecord(document)) return null
  if ("Results" in document) return "trivy-json"
  if ("matches" in document) return "grype-json"
  if (String(document.bomFormat ?? "").includes("CycloneDX")) {
    return "cyclonedx-json"
  }
  if ("spdxVersion" in document) return "spdx-json"
  if ("scanInfo" in document && "dependencies" in document) {
    return "dependency-check-json"
  }
  if ("alerts" in document || "security_advisory" in document) {
    return "github-alerts-json"
  }
  return null
}

function cveListPreview(
  base: ParserPreview,
  text: string,
  fileName: string,
): ParserPreview {
  let values: CveValue[]
  if (fileName.toLowerCase().endsWith(".csv")) {
    const [header, ...rows] = csvRecords(text)
    const column = columnIndex(header, "cve_id")
    if (column < 0) {
      return {
        ...base,
        missingRequiredFields: ["cve_id column"],
        requiredFieldsFound: [],
        state: "error",
        errors: ["CSV input must contain a cve_id column."],
      }
    }
    values = rows
      .map((row) => ({ line: row.line, value: (row.cells[column] ?? "").trim() }))
      .filter((row) => row.value)
  } else {
    values = text
      .split(/\r?\n/)
      .map((raw, index) => ({ line: index + 1, value: raw.trim() }))
      .filter((row) => row.value && !row.value.startsWith(COMMENT_PREFIX))
  }
  return cveValuesPreview(base, values, "CVE identifier")
}

function occurrenceCsvPreview(base: ParserPreview, text: string): ParserPreview {
  const [header, ...rows] = csvRecords(text)
  const column = columnIndex(header, "cve_id")
  if (column < 0) {
    return {
      ...base,
      missingRequiredFields: ["CVE column"],
      requiredFieldsFound: [],
      state: "error",
      errors: ["Missing required CSV header: cve_id."],
    }
  }
  const values = rows.map((row) => ({
    line: row.line,
    value: (row.cells[column] ?? "").trim(),
  }))
  return cveValuesPreview(base, values, "CVE column")
}

/** Counts valid CVE values; any invalid one stops the import, so says so. */
function cveValuesPreview(
  base: ParserPreview,
  values: readonly CveValue[],
  requiredField: string,
): ParserPreview {
  const invalid = values.filter((row) => !CVE_ID.test(row.value))
  const valid = values.length - invalid.length
  if (values.length === 0) {
    return {
      ...base,
      candidateRows: 0,
      invalidRows: 0,
      missingRequiredFields: [requiredField],
      requiredFieldsFound: [],
      state: "error",
      errors: ["No CVE identifiers detected."],
    }
  }
  if (invalid.length > 0) {
    return {
      ...base,
      candidateRows: valid,
      invalidLines: invalid.map((row) => row.line),
      invalidRows: invalid.length,
      requiredFieldsFound: [requiredField],
      state: "error",
      errors: [invalidLinesMessage(invalid)],
    }
  }
  return {
    ...base,
    candidateRows: valid,
    invalidRows: 0,
    missingRequiredFields: [],
    requiredFieldsFound: [requiredField],
  }
}

function invalidLinesMessage(invalid: readonly CveValue[]) {
  const listed = invalid
    .slice(0, LISTED_INVALID_LINES)
    .map((row) => `line ${row.line} ("${shortValue(row.value)}")`)
    .join(", ")
  const more =
    invalid.length > LISTED_INVALID_LINES
      ? ` and ${invalid.length - LISTED_INVALID_LINES} more`
      : ""
  const count = invalid.length === 1 ? "A line is" : `${invalid.length} lines are`
  return `${count} not a CVE identifier: ${listed}${more}. The import stops at invalid lines, so fix or remove them and choose the file again.`
}

function shortValue(value: string) {
  return value.length > 40 ? `${value.slice(0, 39)}…` : value
}

function columnIndex(header: CsvRecord | undefined, name: string) {
  return header
    ? header.cells.findIndex((cell) => cell.trim().toLowerCase() === name)
    : -1
}

/**
 * CSV records as the importer reads them: the delimiter the header uses,
 * quoted cells, and blank or "#" comment records skipped. Each record keeps
 * the line it starts on.
 */
export function csvRecords(text: string): CsvRecord[] {
  const lines = text.split(/\r?\n/)
  const headerLine =
    lines.find((line) => line.trim() && !line.trim().startsWith(COMMENT_PREFIX)) ??
    ""
  const delimiter = csvDelimiter(headerLine)
  const records: CsvRecord[] = []
  let cells: string[] = []
  let cell = ""
  let quoted = false
  let startLine = 1
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? ""
    if (!quoted) {
      startLine = index + 1
      cells = []
      cell = ""
    } else {
      cell += "\n"
    }
    for (let position = 0; position < line.length; position += 1) {
      const character = line[position]
      if (quoted) {
        if (character === '"' && line[position + 1] === '"') {
          cell += '"'
          position += 1
        } else if (character === '"') {
          quoted = false
        } else {
          cell += character
        }
      } else if (character === '"' && cell === "") {
        quoted = true
      } else if (character === delimiter) {
        cells.push(cell)
        cell = ""
      } else {
        cell += character
      }
    }
    if (quoted) continue
    cells.push(cell)
    const blank = cells.every((value) => !value.trim())
    if (!blank && !(cells[0] ?? "").trim().startsWith(COMMENT_PREFIX)) {
      records.push({ cells, line: startLine })
    }
  }
  return records
}

function csvDelimiter(headerLine: string) {
  let best: (typeof CSV_DELIMITERS)[number] = ","
  let bestCount = 0
  for (const delimiter of CSV_DELIMITERS) {
    const count = headerLine.split(delimiter).length - 1
    if (count > bestCount) {
      best = delimiter
      bestCount = count
    }
  }
  return best
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}
