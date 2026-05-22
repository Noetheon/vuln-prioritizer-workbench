import { Input } from "@/components/ui/input"
import { VpwField } from "@/components/vpw"

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

export function RangeFilter({
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
    <VpwField className="vpw-filter-field vpw-filter-field--md" label={name}>
      <div className="flex min-w-0 items-center gap-2">
        <Input
          aria-label={minLabel}
          className="vpw-filter-control h-9 w-20 text-sm"
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
          className="vpw-filter-control h-9 w-20 text-sm"
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
    </VpwField>
  )
}
