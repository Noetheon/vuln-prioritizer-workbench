import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export type VpwToolbarProps = {
  children: ReactNode
  className?: string
  label?: string
}

export type VpwToolbarGroupProps = {
  children: ReactNode
  className?: string
}

export function VpwToolbar({ children, className, label }: VpwToolbarProps) {
  const accessibilityProps = label
    ? ({ "aria-label": label, role: "toolbar" } as const)
    : {}

  return (
    <div
      className={cn(
        "flex flex-col gap-3 rounded-[var(--vpw-radius-xl)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-3 shadow-[var(--vpw-shadow-1)] sm:flex-row sm:items-center sm:justify-between",
        className,
      )}
      {...accessibilityProps}
    >
      {children}
    </div>
  )
}

export function VpwToolbarGroup({ children, className }: VpwToolbarGroupProps) {
  return (
    <div className={cn("flex flex-wrap items-center gap-2", className)}>
      {children}
    </div>
  )
}
