import type { ReactNode } from "react"

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
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
  neutral:
    "border-[var(--vpw-border-default)] bg-[var(--vpw-bg-panel)] text-[var(--vpw-text-secondary)]",
  success:
    "border-[color-mix(in_srgb,var(--vpw-green)_24%,var(--vpw-bg-card))] bg-[var(--vpw-bg-success)] text-[var(--vpw-green)]",
  warning:
    "border-[color-mix(in_srgb,var(--vpw-amber)_34%,var(--vpw-bg-card))] bg-[var(--vpw-bg-warning)] text-[var(--vpw-amber)]",
  critical:
    "border-[color-mix(in_srgb,var(--vpw-red)_26%,var(--vpw-bg-card))] bg-[var(--vpw-bg-critical)] text-[var(--vpw-red)]",
  info: "border-[color-mix(in_srgb,var(--vpw-blue)_22%,var(--vpw-bg-card))] bg-[var(--vpw-bg-info)] text-[var(--vpw-blue)]",
  support:
    "border-[color-mix(in_srgb,var(--vpw-violet)_22%,var(--vpw-bg-card))] bg-[var(--vpw-bg-panel)] text-[var(--vpw-violet)]",
}

const cardToneClass: Record<VpwMetricTone, string> = {
  neutral: "border-t-[var(--vpw-border-default)]",
  success: "border-t-[var(--vpw-green)]",
  warning: "border-t-[var(--vpw-amber)]",
  critical: "border-t-[var(--vpw-red)]",
  info: "border-t-[var(--vpw-blue)]",
  support: "border-t-[var(--vpw-violet)]",
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
    <Card
      className={cn(
        "vpw-card min-h-[8rem] gap-0 overflow-hidden border-t-2 py-0",
        cardToneClass[tone],
        className,
      )}
    >
      <CardHeader className="flex-row items-start justify-between gap-3 px-4 pb-2 pt-4">
        <div className="min-w-0">
          <CardDescription className="vpw-label leading-4">
            {label}
          </CardDescription>
        </div>
        {icon ? (
          <div
            className={cn(
              "flex size-8 shrink-0 items-center justify-center rounded-[var(--vpw-radius-md)] border",
              iconToneClass[tone],
            )}
          >
            {icon}
          </div>
        ) : null}
      </CardHeader>
      <CardContent className="px-4 pb-4 pt-0">
        <CardTitle className="text-2xl font-semibold leading-tight text-[var(--vpw-text-primary)]">
          {value}
        </CardTitle>
        {description ? (
          <p
            className="mt-2 line-clamp-2 text-sm leading-5 text-[var(--vpw-text-secondary)]"
            title={description}
          >
            {description}
          </p>
        ) : null}
      </CardContent>
    </Card>
  )
}
