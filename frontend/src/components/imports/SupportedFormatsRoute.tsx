import { Link } from "@/lib/router"
import { Search, Upload } from "lucide-react"
import { useMemo, useState } from "react"
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
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwKeyValueList,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
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

export function SupportedFormatsRoute({ selectedProjectId }: ImportsWorkbenchProps) {
  const [query, setQuery] = useState("")
  const [category, setCategory] = useState<CategoryFilter>("all")
  const [selectedInputType, setSelectedInputType] = useState(
    SUPPORTED_IMPORT_FORMATS[0].inputType,
  )
  const selectedFormat =
    SUPPORTED_IMPORT_FORMATS.find((format) => format.inputType === selectedInputType) ??
    SUPPORTED_IMPORT_FORMATS[0]
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
  const projectSearch = selectedProjectRouteSearch(selectedProjectId)
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
    { id: "category", header: "Category", cell: (format) => format.categoryLabel },
    { id: "extensions", header: "Extensions", cell: (format) => format.extensions.join(", ") },
    { id: "best", header: "Best for", cell: (format) => format.bestFor },
    { id: "shape", header: "Expected shape", cell: (format) => format.expectedShape },
    {
      id: "context",
      header: "Context support",
      cell: (format) => format.contextSupport.replaceAll("-", " "),
    },
    {
      id: "example",
      header: "Example",
      cell: (format) => (
        <code className="text-xs text-[var(--vpw-text-secondary)]">
          {format.exampleSnippet.slice(0, 40)}
        </code>
      ),
    },
  ]

  return (
    <div className="imports-page-shell mx-auto flex w-full max-w-[1480px] flex-col gap-6">
      <VpwSection>
        <VpwSectionHeader
          actions={
            <>
              <Button asChild variant="outline">
                <Link search={projectSearch} to="/imports">
                  Back to imports
                </Link>
              </Button>
              <Button asChild>
                <Link
                  search={importFormatUrlSearch(
                    projectSearchString(selectedProjectId),
                    selectedFormat.inputType,
                  )}
                  to="/imports/new"
                >
                  <Upload aria-hidden="true" data-icon="inline-start" />
                  New import
                </Link>
              </Button>
            </>
          }
          description="File formats and structure expectations for imports."
          title="Supported formats"
        />
      </VpwSection>

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
                    {Object.entries(FORMAT_CATEGORY_LABELS).map(([value, label]) => (
                      <SelectItem key={value} value={value}>
                        {label}
                      </SelectItem>
                    ))}
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
              getRowKey={(format) => format.inputType}
              minWidth="1100px"
            />
          ) : (
            <VpwEmptyState
              description="Clear search or category filters to see all supported formats."
              title="No supported format matches your search"
            />
          )}
        </VpwPanel>
        <SupportedFormatDetailPanel
          format={selectedFormat}
          projectId={selectedProjectId}
        />
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
            value: format.optionalFields.length > 0 ? format.optionalFields.join(", ") : "None",
          },
          {
            label: "Context support",
            value: format.contextSupport.replaceAll("-", " "),
          },
        ]}
      />
      <div>
        <p className="vpw-label">Example snippet</p>
        <pre className="mt-2 max-h-48 overflow-auto rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-panel)] p-3 text-xs text-[var(--vpw-text-primary)]">
          <code>{format.exampleSnippet}</code>
        </pre>
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
