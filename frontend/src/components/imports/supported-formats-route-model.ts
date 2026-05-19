import {
  SUPPORTED_IMPORT_FORMATS,
  type SupportedFormatCategory,
} from "@/lib/import-format-metadata"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"

export type CategoryFilter = "all" | SupportedFormatCategory

export function filterSupportedFormats(
  query: string,
  category: CategoryFilter,
) {
  const normalizedQuery = query.trim().toLowerCase()
  return SUPPORTED_IMPORT_FORMATS.filter((format) => {
    if (category !== "all" && format.category !== category) return false
    if (!normalizedQuery) return true
    return [
      format.label,
      format.categoryLabel,
      format.bestFor,
      format.expectedShape,
      format.extensions.join(" "),
    ]
      .join(" ")
      .toLowerCase()
      .includes(normalizedQuery)
  })
}

export function projectSearchString(projectId: string) {
  return new URLSearchParams(
    selectedProjectRouteSearch(projectId) as Record<string, string>,
  ).toString()
}
