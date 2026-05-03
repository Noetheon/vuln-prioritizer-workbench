import { cn } from "@/lib/utils"

export type VpwProgressTone =
  | "neutral"
  | "info"
  | "success"
  | "warning"
  | "critical"
  | "support"

export type VpwProgressProps = {
  label: string
  value: number
  className?: string
  max?: number
  showValue?: boolean
  tone?: VpwProgressTone
}

const barToneClass: Record<VpwProgressTone, string> = {
  neutral: "bg-[var(--vpw-text-muted)]",
  info: "bg-[var(--vpw-blue)]",
  success: "bg-[var(--vpw-green)]",
  warning: "bg-[var(--vpw-amber)]",
  critical: "bg-[var(--vpw-red)]",
  support: "bg-[var(--vpw-violet)]",
}

export function VpwProgress({
  className,
  label,
  max = 100,
  showValue = true,
  tone = "info",
  value,
}: VpwProgressProps) {
  const safeMax = max > 0 ? max : 100
  const percent = Math.min(100, Math.max(0, (value / safeMax) * 100))

  return (
    <div className={cn("grid gap-2", className)}>
      <div className="flex items-center justify-between gap-3 text-sm">
        <span className="font-medium text-[var(--vpw-text-primary)]">
          {label}
        </span>
        {showValue ? (
          <span className="text-[var(--vpw-text-muted)]">
            {Math.round(percent)}%
          </span>
        ) : null}
      </div>
      <div
        aria-label={label}
        aria-valuemax={safeMax}
        aria-valuemin={0}
        aria-valuenow={value}
        className="h-2 overflow-hidden rounded-[var(--vpw-radius-pill)] bg-[var(--vpw-border-subtle)]"
        role="progressbar"
      >
        <div
          className={cn(
            "h-full rounded-[var(--vpw-radius-pill)]",
            barToneClass[tone],
          )}
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  )
}
