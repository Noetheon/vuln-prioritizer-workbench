import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export type VpwToolbarProps = {
  children: ReactNode
  className?: string
  label?: string
  variant?: "framed" | "plain"
}

export type VpwToolbarGroupProps = {
  children: ReactNode
  className?: string
}

const toolbarVariantClass: Record<NonNullable<VpwToolbarProps["variant"]>, string> =
  {
    framed:
      "rounded-[var(--vpw-radius-xl)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-3 shadow-[var(--vpw-shadow-1)]",
    plain: "p-0",
  }

export function VpwToolbar({
  children,
  className,
  label,
  variant = "framed",
}: VpwToolbarProps) {
  const accessibilityProps = label
    ? ({ "aria-label": label, role: "toolbar" } as const)
    : {}

  return (
    <div
      className={cn(
        "flex min-w-0 flex-col gap-3 sm:flex-row sm:items-center sm:justify-between",
        toolbarVariantClass[variant],
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
    <div className={cn("flex min-w-0 flex-wrap items-center gap-2", className)}>
      {children}
    </div>
  )
}
