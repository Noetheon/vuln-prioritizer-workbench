import { Search } from "lucide-react"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { FORMAT_CATEGORY_LABELS } from "@/lib/import-format-metadata"
import type { CategoryFilter } from "./supported-formats-route-model"

type SupportedFormatsFiltersProps = {
  category: CategoryFilter
  onCategoryChange: (category: CategoryFilter) => void
  onQueryChange: (query: string) => void
  query: string
}

export function SupportedFormatsFilters({
  category,
  onCategoryChange,
  onQueryChange,
  query,
}: SupportedFormatsFiltersProps) {
  return (
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
            onChange={(event) => onQueryChange(event.target.value)}
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
          onValueChange={(value) => onCategoryChange(value as CategoryFilter)}
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
  )
}
