import type { ReactNode } from "react"

import { Badge, type BadgeProps } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

export type BadgeDensity = "default" | "compact"

export type VpwBadgeTone =
  | "neutral"
  | "info"
  | "success"
  | "warning"
  | "critical"
  | "support"

export type VpwBadgeProps = Omit<BadgeProps, "children" | "variant"> & {
  children: ReactNode
  density?: BadgeDensity
  overflow?: "truncate" | "wrap"
  tone?: VpwBadgeTone
}

const toneClass: Record<VpwBadgeTone, string> = {
  neutral: "vpw-badge-neutral",
  info: "vpw-badge-info",
  success: "vpw-badge-success",
  warning: "vpw-badge-warning",
  critical: "vpw-badge-critical",
  support: "vpw-badge-support",
}

export function VpwBadge({
  children,
  className,
  density = "default",
  overflow = "truncate",
  title,
  tone = "neutral",
  ...props
}: VpwBadgeProps) {
  return (
    <Badge
      className={cn(
        "vpw-badge",
        `vpw-badge--${density}`,
        `vpw-badge--${overflow}`,
        toneClass[tone],
        className,
      )}
      title={title ?? textTitle(children)}
      variant="outline"
      {...props}
    >
      <span className="vpw-badge__label">{children}</span>
    </Badge>
  )
}

function textTitle(children: ReactNode): string | undefined {
  if (typeof children === "string" || typeof children === "number") {
    return String(children)
  }
  if (!Array.isArray(children)) return undefined

  const text = children
    .map((child) =>
      typeof child === "string" || typeof child === "number"
        ? String(child)
        : "",
    )
    .join("")
    .trim()
  return text || undefined
}
