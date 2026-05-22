import {
  CheckCircle2,
  Circle,
  Clock,
  type LucideIcon,
  XCircle,
} from "lucide-react"
import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export type VpwTimelineTone = "neutral" | "success" | "warning" | "critical"

export type VpwTimelineItem = {
  id?: string
  title: string
  description?: ReactNode
  meta?: ReactNode
  tone?: VpwTimelineTone
}

export type VpwTimelineProps = {
  items: readonly VpwTimelineItem[]
  className?: string
}

const toneClass: Record<VpwTimelineTone, string> = {
  neutral: "text-[var(--vpw-text-muted)]",
  success: "text-[var(--vpw-green)]",
  warning: "text-[var(--vpw-amber)]",
  critical: "text-[var(--vpw-red)]",
}

const toneIcon: Record<VpwTimelineTone, LucideIcon> = {
  neutral: Circle,
  success: CheckCircle2,
  warning: Clock,
  critical: XCircle,
}

export function VpwTimeline({ className, items }: VpwTimelineProps) {
  return (
    <ol className={cn("grid gap-4", className)}>
      {items.map((item, index) => {
        const tone = item.tone ?? "neutral"
        const Icon = toneIcon[tone]

        return (
          <li
            className="relative grid grid-cols-[1.25rem_1fr] gap-3"
            key={item.id ?? item.title}
          >
            {index < items.length - 1 ? (
              <span
                aria-hidden="true"
                className="absolute left-2 top-6 h-[calc(100%+0.5rem)] w-px bg-[var(--vpw-border-subtle)]"
              />
            ) : null}
            <Icon
              aria-hidden="true"
              className={cn(
                "relative z-10 mt-0.5 h-4 w-4 bg-[var(--vpw-bg-card)]",
                toneClass[tone],
              )}
            />
            <div className="min-w-0">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <p className="font-medium text-[var(--vpw-text-primary)]">
                  {item.title}
                </p>
                {item.meta ? (
                  <span className="text-xs text-[var(--vpw-text-muted)]">
                    {item.meta}
                  </span>
                ) : null}
              </div>
              {item.description ? (
                <div className="mt-1 text-sm leading-5 text-[var(--vpw-text-secondary)]">
                  {item.description}
                </div>
              ) : null}
            </div>
          </li>
        )
      })}
    </ol>
  )
}
