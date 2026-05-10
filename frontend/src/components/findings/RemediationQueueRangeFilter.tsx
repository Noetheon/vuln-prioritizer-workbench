import { Input } from "@/components/ui/input"

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
    <div className="flex flex-col gap-1">
      <span className="text-[11px] font-semibold uppercase text-muted-foreground">
        {name}
      </span>
      <div className="flex items-center gap-1">
        <Input
          aria-label={minLabel}
          className="h-10 w-20 text-sm"
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
          className="h-10 w-20 text-sm"
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
