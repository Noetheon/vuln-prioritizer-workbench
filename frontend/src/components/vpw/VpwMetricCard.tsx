import type { ReactNode } from "react"

import { Card, CardContent } from "@/components/ui/card"
import { cn } from "@/lib/utils"

export type VpwMetricTone =
  | "neutral"
  | "success"
  | "warning"
  | "critical"
  | "info"
  | "support"

export type VpwMetricCardProps = {
  label: string
  value: ReactNode
  className?: string
  description?: string
  icon?: ReactNode
  tone?: VpwMetricTone
}

const iconToneClass: Record<VpwMetricTone, string> = {
  neutral: "bg-[var(--vpw-bg-panel)] text-[var(--vpw-text-secondary)]",
  success: "bg-[var(--vpw-bg-success)] text-[var(--vpw-green)]",
  warning: "bg-[var(--vpw-bg-warning)] text-[var(--vpw-amber)]",
  critical: "bg-[var(--vpw-bg-critical)] text-[var(--vpw-red)]",
  info: "bg-[var(--vpw-bg-info)] text-[var(--vpw-blue)]",
  support: "bg-[var(--vpw-bg-panel)] text-[var(--vpw-violet)]",
}

export function VpwMetricCard({
  className,
  description,
  icon,
  label,
  tone = "neutral",
  value,
}: VpwMetricCardProps) {
  return (
    <Card className={cn("vpw-card py-0", className)}>
      <CardContent className="flex min-h-28 items-start justify-between gap-4 p-6">
        <div className="min-w-0">
          <p className="vpw-label">{label}</p>
          <div className="mt-2 text-3xl font-bold text-[var(--vpw-text-primary)]">
            {value}
          </div>
          {description ? (
            <p className="mt-1 text-sm leading-5 text-[var(--vpw-text-secondary)]">
              {description}
            </p>
          ) : null}
        </div>
        {icon ? (
          <div
            className={cn(
              "rounded-[var(--vpw-radius-lg)] p-2",
              iconToneClass[tone],
            )}
          >
            {icon}
          </div>
        ) : null}
      </CardContent>
    </Card>
  )
}
