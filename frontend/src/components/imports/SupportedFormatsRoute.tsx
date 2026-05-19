import { Link } from "@/lib/router"
import { Upload } from "lucide-react"
import { useEffect, useMemo, useState } from "react"
import { Button } from "@/components/ui/button"
import {
  VpwDataTable,
  VpwEmptyState,
  VpwPanel,
} from "@/components/vpw"
import { SUPPORTED_IMPORT_FORMATS } from "@/lib/import-format-metadata"
import { importFormatUrlSearch } from "@/workbench/import-route-search"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import { buildSupportedFormatColumns } from "./SupportedFormatsColumns"
import { SupportedFormatDetailPanel } from "./SupportedFormatDetailPanel"
import { SupportedFormatsFilters } from "./SupportedFormatsFilters"
import type { ImportsWorkbenchProps } from "./imports-workbench-model"
import {
  filterSupportedFormats,
  projectSearchString,
  type CategoryFilter,
} from "./supported-formats-route-model"

export function SupportedFormatsRoute({
  selectedProjectId,
}: ImportsWorkbenchProps) {
  const [query, setQuery] = useState("")
  const [category, setCategory] = useState<CategoryFilter>("all")
  const [selectedInputType, setSelectedInputType] = useState(
    SUPPORTED_IMPORT_FORMATS[0].inputType,
  )
  const filteredFormats = useMemo(
    () => filterSupportedFormats(query, category),
    [category, query],
  )
  const selectedFormat =
    filteredFormats.find((format) => format.inputType === selectedInputType) ??
    null

  useEffect(() => {
    if (filteredFormats.length === 0) return
    if (
      filteredFormats.some((format) => format.inputType === selectedInputType)
    ) {
      return
    }
    setSelectedInputType(filteredFormats[0].inputType)
  }, [filteredFormats, selectedInputType])

  const projectSearch = selectedProjectRouteSearch(selectedProjectId)
  const newImportSearch = selectedFormat
    ? importFormatUrlSearch(
        projectSearchString(selectedProjectId),
        selectedFormat.inputType,
      )
    : projectSearch
  const columns = buildSupportedFormatColumns({
    onSelectInputType: setSelectedInputType,
    selectedInputType,
  })

  return (
    <div className="imports-page-shell flex w-full min-w-0 flex-col gap-6">
      <div className="flex flex-wrap justify-end gap-2">
        <Button asChild variant="outline">
          <Link search={projectSearch} to="/imports">
            Back to imports
          </Link>
        </Button>
        <Button asChild>
          <Link search={newImportSearch} to="/imports/new">
            <Upload aria-hidden="true" data-icon="inline-start" />
            New import
          </Link>
        </Button>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_380px]">
        <VpwPanel className="flex min-w-0 flex-col gap-4">
          <SupportedFormatsFilters
            category={category}
            onCategoryChange={setCategory}
            onQueryChange={setQuery}
            query={query}
          />
          {filteredFormats.length > 0 ? (
            <VpwDataTable
              caption="Supported import formats"
              columns={columns}
              data={filteredFormats}
              density="compact"
              getRowClassName={(format) =>
                format.inputType === selectedInputType
                  ? "vpw-table-row--selected"
                  : undefined
              }
              getRowKey={(format) => format.inputType}
              minWidth="960px"
            />
          ) : (
            <VpwEmptyState
              action={
                <Button
                  onClick={() => {
                    setQuery("")
                    setCategory("all")
                  }}
                  type="button"
                  variant="outline"
                >
                  Clear search
                </Button>
              }
              description="Try another search or clear filters."
              title={`No supported format matches${query.trim() ? ` "${query.trim()}"` : " your filters"}.`}
            />
          )}
        </VpwPanel>
        {selectedFormat ? (
          <SupportedFormatDetailPanel
            format={selectedFormat}
            projectId={selectedProjectId}
          />
        ) : null}
      </div>
    </div>
  )
}
