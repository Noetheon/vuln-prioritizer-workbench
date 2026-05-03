import type { ReactNode } from "react"

import { Badge, type BadgeProps } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

export type VpwBadgeTone =
  | "neutral"
  | "info"
  | "success"
  | "warning"
  | "critical"
  | "support"

export type VpwBadgeProps = Omit<BadgeProps, "children" | "variant"> & {
  children: ReactNode
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
  tone = "neutral",
  ...props
}: VpwBadgeProps) {
  return (
    <Badge
      className={cn("vpw-badge", toneClass[tone], className)}
      variant="outline"
      {...props}
    >
      {children}
    </Badge>
  )
}
