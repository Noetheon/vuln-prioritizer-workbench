import type {
  AssetExposure,
  FindingPriority,
  FindingStatus,
} from "@/api-client"
import { VpwField, VpwSelectControl } from "@/components/vpw"
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
      <VpwField className="vpw-filter-field vpw-filter-field--sm" label="Priority">
        <VpwSelectControl
          ariaLabel="Priority"
          onValueChange={(v) =>
            onFilterChange(
              "priority",
              v === "__all" ? "" : (v as FindingPriority),
            )
          }
          options={[
            { label: "All", value: "__all" },
            ...priorityOptions.map((p) => ({
              label: labelize(p),
              value: p,
            })),
          ]}
          value={findingFilters.priority || "__all"}
        />
      </VpwField>

      <VpwField className="vpw-filter-field vpw-filter-field--sm" label="Status">
        <VpwSelectControl
          ariaLabel="Status"
          onValueChange={(v) =>
            onFilterChange("status", v === "__all" ? "" : (v as FindingStatus))
          }
          options={[
            { label: "All", value: "__all" },
            ...statusOptions.map((s) => ({
              label: labelize(s),
              value: s,
            })),
          ]}
          value={findingFilters.status || "__all"}
        />
      </VpwField>
    </>
  )
}

export function AdvancedFilterSelects({
  findingFilters,
  onFilterChange,
}: FilterSelectsProps) {
  return (
    <>
      <VpwField className="vpw-filter-field vpw-filter-field--sm" label="KEV">
        <VpwSelectControl
          ariaLabel="KEV"
          onValueChange={(v) =>
            onFilterChange("kev", v === "__all" ? "" : (v as KevFilter))
          }
          options={[
            { label: "Any", value: "__all" },
            { label: "KEV", value: "true" },
            { label: "Not KEV", value: "false" },
          ]}
          value={findingFilters.kev || "__all"}
        />
      </VpwField>

      <VpwField className="vpw-filter-field vpw-filter-field--md" label="Exposure">
        <VpwSelectControl
          ariaLabel="Exposure"
          onValueChange={(v) =>
            onFilterChange(
              "exposure",
              v === "__all" ? "" : (v as AssetExposure),
            )
          }
          options={[
            { label: "Any", value: "__all" },
            ...exposureOptions.map((e) => ({
              label: labelize(e),
              value: e,
            })),
          ]}
          value={findingFilters.exposure || "__all"}
        />
      </VpwField>

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
    </>
  )
}
