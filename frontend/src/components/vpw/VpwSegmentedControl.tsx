import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

export type VpwSegmentOption = {
  label: string
  value: string
}

export type VpwSegmentedControlProps = {
  options: readonly VpwSegmentOption[]
  value: string
  className?: string
  label?: string
  onChange?: (value: string) => void
}

export function VpwSegmentedControl({
  className,
  label,
  onChange,
  options,
  value,
}: VpwSegmentedControlProps) {
  return (
    <fieldset
      className={cn(
        "vpw-segmented-control inline-flex rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-panel)] p-1",
        className,
      )}
    >
      {label ? <legend className="sr-only">{label}</legend> : null}
      {options.map((option) => (
        <Button
          aria-pressed={option.value === value}
          className={cn(
            "h-8 rounded-[var(--vpw-radius-sm)] px-3 text-sm font-medium text-[var(--vpw-text-secondary)] transition-colors",
            option.value === value &&
              "bg-[var(--vpw-bg-card)] text-[var(--vpw-text-primary)] shadow-[var(--vpw-shadow-1)]",
          )}
          key={option.value}
          onClick={() => onChange?.(option.value)}
          size="sm"
          type="button"
          variant="ghost"
        >
          {option.label}
        </Button>
      ))}
    </fieldset>
  )
}
