import type {
  ImportFormatCapabilityPublic,
  WorkbenchCapabilitiesPublic,
} from "../api-client"
import type {
  ImportInputType,
  SupportedFormat,
} from "./import-format-types.ts"

export function importFormatFromCapability(
  capability: ImportFormatCapabilityPublic,
): SupportedFormat {
  return {
    acceptedMimeTypes: capability.accepted_mime_types ?? [],
    bestFor: capability.best_for,
    category: capability.category,
    categoryLabel: capability.category_label,
    contextSupport: capability.context_support,
    exampleSnippet: capability.example_snippet,
    expectedShape: capability.expected_shape,
    extensions: capability.extensions ?? [],
    inputType: capability.input_type,
    label: capability.label,
    minimumFields: capability.minimum_fields ?? [],
    notes: capability.notes ?? [],
    optionalFields: capability.optional_fields ?? [],
    shortDescription: capability.short_description,
  }
}

export function supportedImportFormats(
  capabilities: WorkbenchCapabilitiesPublic | null | undefined,
): SupportedFormat[] {
  return (capabilities?.import_formats ?? []).map(importFormatFromCapability)
}

export function supportedImportCategories(formats: readonly SupportedFormat[]) {
  const categories = new Map<string, string>()
  for (const format of formats) {
    if (!categories.has(format.category)) {
      categories.set(format.category, format.categoryLabel)
    }
  }
  return [...categories.entries()].map(([category, label]) => ({
    category,
    label,
  }))
}

export function isImportInputType(
  formats: readonly SupportedFormat[],
  value: string | null | undefined,
): value is ImportInputType {
  return Boolean(value && formats.some((format) => format.inputType === value))
}

export function getImportFormat(
  formats: readonly SupportedFormat[],
  inputType: string | null | undefined,
): SupportedFormat | undefined {
  return formats.find((format) => format.inputType === inputType)
}

export function getAcceptedExtensions(
  formats: readonly SupportedFormat[],
  inputType: string | null | undefined,
) {
  return getImportFormat(formats, inputType)?.extensions ?? []
}

export function getAcceptedMimeTypes(
  formats: readonly SupportedFormat[],
  inputType: string | null | undefined,
) {
  return getImportFormat(formats, inputType)?.acceptedMimeTypes ?? []
}

export function acceptedFileInputValue(format: SupportedFormat | undefined) {
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
  formats: readonly SupportedFormat[],
  file: File | null | undefined,
  inputType: string | null | undefined,
) {
  if (!file || !isImportInputType(formats, inputType)) return false
  const lowerName = file.name.toLowerCase()
  const extensions = getAcceptedExtensions(formats, inputType)
  return extensions.some((extension) => lowerName.endsWith(extension))
}
