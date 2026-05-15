import type { LucideIcon } from "lucide-react"
import type { ReactNode } from "react"
import { VpwSurface, VpwSurfaceBody } from "@/components/vpw"
import { cn } from "@/lib/utils"

type MetricCardProps = {
  detail: ReactNode
  icon: LucideIcon
  label: string
  tone: string
  value: ReactNode
  className?: string
}

const accentStyles: Record<string, string> = {
  accepted: "border-l-[var(--vpw-green)]",
  critical: "border-l-[var(--vpw-red)]",
  exposure: "border-l-[var(--vpw-blue)]",
  high: "border-l-[var(--vpw-amber)]",
  kev: "border-l-[var(--vpw-violet)]",
  low: "border-l-[var(--vpw-green)]",
  medium: "border-l-[var(--vpw-amber)]",
  run: "border-l-[var(--vpw-teal)]",
  standard: "border-l-[var(--vpw-border-strong)]",
}

const iconBgStyles: Record<string, string> = {
  accepted: "bg-[var(--vpw-bg-success)] text-[var(--vpw-green)]",
  critical: "bg-[var(--vpw-bg-critical)] text-[var(--vpw-red)]",
  exposure: "bg-[var(--vpw-bg-info)] text-[var(--vpw-blue)]",
  high: "bg-[var(--vpw-bg-warning)] text-[var(--vpw-amber)]",
  kev: "bg-[var(--vpw-bg-panel)] text-[var(--vpw-violet)]",
  low: "bg-[var(--vpw-bg-success)] text-[var(--vpw-green)]",
  medium: "bg-[var(--vpw-bg-warning)] text-[var(--vpw-amber)]",
  run: "bg-[var(--vpw-bg-success)] text-[var(--vpw-teal)]",
  standard: "bg-[var(--vpw-bg-panel)] text-[var(--vpw-text-secondary)]",
}

export function MetricCard({
  detail,
  icon: Icon,
  label,
  tone,
  value,
  className,
}: MetricCardProps) {
  return (
    <VpwSurface
      aria-label={`${label} summary card`}
      className={cn(
        "border-l-4 transition-all hover:shadow-[var(--vpw-shadow-2)]",
        accentStyles[tone] ?? accentStyles.standard,
        className,
      )}
    >
      <VpwSurfaceBody className="p-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <p className="vpw-label truncate text-[11px]">{label}</p>
            <p className="mt-1 text-2xl font-bold leading-none text-[var(--vpw-text-primary)]">
              {value}
            </p>
            <p className="mt-0.5 truncate text-xs text-[var(--vpw-text-muted)]">
              {detail}
            </p>
          </div>
          <div
            className={cn(
              "shrink-0 rounded-[var(--vpw-radius-md)] p-1.5",
              iconBgStyles[tone] ?? iconBgStyles.standard,
            )}
          >
            <Icon size={18} />
          </div>
        </div>
      </VpwSurfaceBody>
    </VpwSurface>
  )
}
