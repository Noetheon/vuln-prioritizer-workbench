import { Link } from "@/lib/router"
import { Search, Upload } from "lucide-react"
import { useEffect, useMemo, useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  MetaTag,
  VpwCodeBlock,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwKeyValueList,
  VpwPanel,
} from "@/components/vpw"
import {
  FORMAT_CATEGORY_LABELS,
  SUPPORTED_IMPORT_FORMATS,
  type SupportedFormat,
  type SupportedFormatCategory,
} from "@/lib/import-format-metadata"
import { importFormatUrlSearch } from "@/workbench/import-route-search"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import type { ImportsWorkbenchProps } from "./imports-workbench-model"

type CategoryFilter = "all" | SupportedFormatCategory

export function SupportedFormatsRoute({
  selectedProjectId,
}: ImportsWorkbenchProps) {
  const [query, setQuery] = useState("")
  const [category, setCategory] = useState<CategoryFilter>("all")
  const [selectedInputType, setSelectedInputType] = useState(
    SUPPORTED_IMPORT_FORMATS[0].inputType,
  )
  const filteredFormats = useMemo(() => {
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
  }, [category, query])
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
  const columns: VpwDataTableColumn<SupportedFormat>[] = [
    {
      id: "format",
      header: "Format",
      cell: (format) => (
        <Button
          className="text-left font-medium text-[var(--vpw-text-primary)] underline-offset-4 hover:underline"
          onClick={() => setSelectedInputType(format.inputType)}
          size="sm"
          type="button"
          variant="link"
        >
          {format.label}
        </Button>
      ),
    },
    {
      id: "category",
      header: "Category",
      cell: (format) => format.categoryLabel,
    },
    {
      id: "extensions",
      header: "Extensions",
      cell: (format) => format.extensions.join(", "),
    },
    { id: "best", header: "Best for", cell: (format) => format.bestFor },
    {
      id: "shape",
      header: "Expected shape",
      cell: (format) => format.expectedShape,
    },
    {
      id: "context",
      header: "Context support",
      cell: (format) => format.contextSupport.replaceAll("-", " "),
    },
    {
      id: "details",
      header: "Details",
      cell: (format) => (
        <Button
          className="w-full justify-center whitespace-nowrap px-2"
          onClick={() => setSelectedInputType(format.inputType)}
          size="sm"
          type="button"
          variant={
            format.inputType === selectedInputType ? "secondary" : "outline"
          }
        >
          View details
        </Button>
      ),
      width: "128px",
    },
  ]

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
          <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_220px]">
            <div className="grid gap-2">
              <label className="vpw-label" htmlFor="imports-format-search">
                Search formats
              </label>
              <span className="relative">
                <Search
                  aria-hidden="true"
                  className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-[var(--vpw-text-muted)]"
                />
                <Input
                  className="pl-9"
                  id="imports-format-search"
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search formats"
                  value={query}
                />
              </span>
            </div>
            <div className="grid gap-2">
              <span className="vpw-label" id="imports-format-category-label">
                Category
              </span>
              <Select
                onValueChange={(value) => setCategory(value as CategoryFilter)}
                value={category}
              >
                <SelectTrigger aria-labelledby="imports-format-category-label">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="all">All formats</SelectItem>
                    {Object.entries(FORMAT_CATEGORY_LABELS).map(
                      ([value, label]) => (
                        <SelectItem key={value} value={value}>
                          {label}
                        </SelectItem>
                      ),
                    )}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </div>
          </div>
          {filteredFormats.length > 0 ? (
            <VpwDataTable
              caption="Supported import formats"
              columns={columns}
              data={filteredFormats}
              density="compact"
              getRowClassName={(format) =>
                format.inputType === selectedInputType
                  ? "[&>td]:bg-[var(--vpw-bg-info)] [&>td:first-child]:shadow-[inset_2px_0_0_var(--vpw-blue)]"
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

function SupportedFormatDetailPanel({
  format,
  projectId,
}: {
  format: SupportedFormat
  projectId: string
}) {
  const search = importFormatUrlSearch(
    projectSearchString(projectId),
    format.inputType,
  )
  const copyExample = () => {
    void navigator.clipboard?.writeText(format.exampleSnippet)
  }
  return (
    <VpwPanel className="flex flex-col gap-4">
      <div>
        <h2 className="text-lg font-semibold text-[var(--vpw-text-primary)]">
          {format.label}
        </h2>
        <div className="mt-3 flex flex-wrap gap-2">
          <MetaTag label={format.categoryLabel} />
          {format.extensions.map((extension) => (
            <MetaTag key={extension} label={extension} />
          ))}
        </div>
      </div>
      <VpwKeyValueList
        items={[
          { label: "About this format", value: format.shortDescription },
          { label: "Best for", value: format.bestFor },
          { label: "Expected shape", value: format.expectedShape },
          { label: "Minimum fields", value: format.minimumFields.join(", ") },
          {
            label: "Optional fields recognized",
            value:
              format.optionalFields.length > 0
                ? format.optionalFields.join(", ")
                : "None",
          },
          {
            label: "Context support",
            value: format.contextSupport.replaceAll("-", " "),
          },
        ]}
      />
      <div>
        <VpwCodeBlock
          code={format.exampleSnippet}
          copyLabel="Copy example"
          label="Example snippet"
          onCopy={copyExample}
        />
      </div>
      {format.notes.length > 0 ? (
        <div className="grid gap-2 text-sm text-[var(--vpw-text-secondary)]">
          {format.notes.map((note) => (
            <p key={note}>{note}</p>
          ))}
        </div>
      ) : null}
      <Button asChild>
        <Link search={search} to="/imports/new">
          Start import with this format
        </Link>
      </Button>
    </VpwPanel>
  )
}

function projectSearchString(projectId: string) {
  return new URLSearchParams(
    selectedProjectRouteSearch(projectId) as Record<string, string>,
  ).toString()
}
