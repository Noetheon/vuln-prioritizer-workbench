import type {
  AssetExposure,
  FindingPriority,
  FindingStatus,
} from "@/api-client"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { formatLabel as labelize } from "@/lib/ui-copy"
import { RangeFilter } from "./RemediationQueueRangeFilter"
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
      <div className="findings-filter-field findings-filter-field--select">
        <span className="vpw-label findings-filter-label">
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
          <SelectTrigger aria-label="Priority" className="h-9 w-full text-sm">
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

      <div className="findings-filter-field findings-filter-field--select">
        <span className="vpw-label findings-filter-label">
          Status
        </span>
        <Select
          onValueChange={(v) =>
            onFilterChange("status", v === "__all" ? "" : (v as FindingStatus))
          }
          value={findingFilters.status || "__all"}
        >
          <SelectTrigger aria-label="Status" className="h-9 w-full text-sm">
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
    <div className="findings-filter-advanced">
      <div className="findings-filter-field findings-filter-field--select">
        <span className="vpw-label findings-filter-label">
          KEV
        </span>
        <Select
          onValueChange={(v) =>
            onFilterChange("kev", v === "__all" ? "" : (v as KevFilter))
          }
          value={findingFilters.kev || "__all"}
        >
          <SelectTrigger aria-label="KEV" className="h-9 w-full text-sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="__all">Any</SelectItem>
            <SelectItem value="true">KEV</SelectItem>
            <SelectItem value="false">Not KEV</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="findings-filter-field findings-filter-field--wide-select">
        <span className="vpw-label findings-filter-label">
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
          <SelectTrigger aria-label="Exposure" className="h-9 w-full text-sm">
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
