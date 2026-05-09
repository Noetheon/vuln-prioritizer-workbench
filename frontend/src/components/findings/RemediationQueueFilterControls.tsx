import type {
  AssetExposure,
  FindingPriority,
  FindingStatus,
} from "@/api-client"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { formatLabel as labelize } from "@/lib/ui-copy"
import {
  exposureOptions,
  type FindingFilters,
  type KevFilter,
  priorityOptions,
  statusOptions,
} from "./remediation-queue-model"

type FilterSelectsProps = {
  findingFilters: FindingFilters
  onFilterChange: <K extends keyof FindingFilters>(
    key: K,
    value: FindingFilters[K],
  ) => void
}

export function PrimaryFilterSelects({
  findingFilters,
  onFilterChange,
}: FilterSelectsProps) {
  return (
    <>
      <div className="flex flex-col gap-1">
        <span className="text-[11px] font-semibold uppercase text-muted-foreground">
          Priority
        </span>
        <Select
          onValueChange={(v) =>
            onFilterChange(
              "priority",
              v === "__all" ? "" : (v as FindingPriority),
            )
          }
          value={findingFilters.priority || "__all"}
        >
          <SelectTrigger aria-label="Priority" className="h-9 w-32 text-sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="__all">All</SelectItem>
            {priorityOptions.map((p) => (
              <SelectItem key={p} value={p}>
                {labelize(p)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="flex flex-col gap-1">
        <span className="text-[11px] font-semibold uppercase text-muted-foreground">
          Status
        </span>
        <Select
          onValueChange={(v) =>
            onFilterChange("status", v === "__all" ? "" : (v as FindingStatus))
          }
          value={findingFilters.status || "__all"}
        >
          <SelectTrigger aria-label="Status" className="h-9 w-36 text-sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="__all">All</SelectItem>
            {statusOptions.map((s) => (
              <SelectItem key={s} value={s}>
                {labelize(s)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    </>
  )
}

export function AdvancedFilterSelects({
  findingFilters,
  onFilterChange,
}: FilterSelectsProps) {
  return (
    <div className="mt-3 flex flex-wrap items-end gap-2 border-t pt-3">
      <div className="flex flex-col gap-1">
        <span className="text-[11px] font-semibold uppercase text-muted-foreground">
          KEV
        </span>
        <Select
          onValueChange={(v) =>
            onFilterChange("kev", v === "__all" ? "" : (v as KevFilter))
          }
          value={findingFilters.kev || "__all"}
        >
          <SelectTrigger aria-label="KEV" className="h-9 w-28 text-sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="__all">Any</SelectItem>
            <SelectItem value="true">KEV</SelectItem>
            <SelectItem value="false">Not KEV</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="flex flex-col gap-1">
        <span className="text-[11px] font-semibold uppercase text-muted-foreground">
          Exposure
        </span>
        <Select
          onValueChange={(v) =>
            onFilterChange(
              "exposure",
              v === "__all" ? "" : (v as AssetExposure),
            )
          }
          value={findingFilters.exposure || "__all"}
        >
          <SelectTrigger aria-label="Exposure" className="h-9 w-40 text-sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="__all">Any</SelectItem>
            {exposureOptions.map((e) => (
              <SelectItem key={e} value={e}>
                {labelize(e)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <RangeFilter
        max="1"
        maxLabel="EPSS max"
        maxValue={findingFilters.epssMax}
        minLabel="EPSS min"
        minValue={findingFilters.epssMin}
        name="EPSS"
        onMaxChange={(value) => onFilterChange("epssMax", value)}
        onMinChange={(value) => onFilterChange("epssMin", value)}
        step="0.01"
      />
      <RangeFilter
        max="10"
        maxLabel="CVSS max"
        maxValue={findingFilters.cvssMax}
        minLabel="CVSS min"
        minValue={findingFilters.cvssMin}
        name="CVSS"
        onMaxChange={(value) => onFilterChange("cvssMax", value)}
        onMinChange={(value) => onFilterChange("cvssMin", value)}
        step="0.1"
      />
    </div>
  )
}

type RangeFilterProps = {
  max: string
  maxLabel: string
  maxValue: string
  minLabel: string
  minValue: string
  name: string
  onMaxChange: (value: string) => void
  onMinChange: (value: string) => void
  step: string
}

function RangeFilter({
  max,
  maxLabel,
  maxValue,
  minLabel,
  minValue,
  name,
  onMaxChange,
  onMinChange,
  step,
}: RangeFilterProps) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-[11px] font-semibold uppercase text-muted-foreground">
        {name}
      </span>
      <div className="flex items-center gap-1">
        <Input
          aria-label={minLabel}
          className="h-9 w-20 text-sm"
          inputMode="decimal"
          max={max}
          min="0"
          onChange={(e) => onMinChange(e.target.value)}
          placeholder="Min"
          step={step}
          type="number"
          value={minValue}
        />
        <span className="text-xs text-muted-foreground">to</span>
        <Input
          aria-label={maxLabel}
          className="h-9 w-20 text-sm"
          inputMode="decimal"
          max={max}
          min="0"
          onChange={(e) => onMaxChange(e.target.value)}
          placeholder="Max"
          step={step}
          type="number"
          value={maxValue}
        />
      </div>
    </div>
  )
}
