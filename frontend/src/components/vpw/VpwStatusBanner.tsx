import {
  AlertTriangle,
  CheckCircle2,
  Info,
  type LucideIcon,
  XCircle,
} from "lucide-react"
import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export type VpwStatusBannerTone = "info" | "success" | "warning" | "critical"

export type VpwStatusBannerProps = {
  title: string
  children?: ReactNode
  action?: ReactNode
  className?: string
  tone?: VpwStatusBannerTone
}

const toneClass: Record<VpwStatusBannerTone, string> = {
  info: "border-[color-mix(in_srgb,var(--vpw-blue)_24%,var(--vpw-bg-card))] bg-[var(--vpw-bg-info)] text-[var(--vpw-blue)]",
  success:
    "border-[color-mix(in_srgb,var(--vpw-green)_28%,var(--vpw-bg-card))] bg-[var(--vpw-bg-success)] text-[color-mix(in_srgb,var(--vpw-green)_50%,var(--vpw-text-primary))]",
  warning:
    "border-[color-mix(in_srgb,var(--vpw-amber)_38%,var(--vpw-bg-card))] bg-[var(--vpw-bg-warning)] text-[color-mix(in_srgb,var(--vpw-amber)_55%,var(--vpw-text-primary))]",
  critical:
    "border-[color-mix(in_srgb,var(--vpw-red)_28%,var(--vpw-bg-card))] bg-[var(--vpw-bg-critical)] text-[color-mix(in_srgb,var(--vpw-red)_65%,var(--vpw-text-primary))]",
}

const toneIcon: Record<VpwStatusBannerTone, LucideIcon> = {
  info: Info,
  success: CheckCircle2,
  warning: AlertTriangle,
  critical: XCircle,
}

export function VpwStatusBanner({
  action,
  children,
  className,
  title,
  tone = "info",
}: VpwStatusBannerProps) {
  const Icon = toneIcon[tone]

  return (
    <div
      className={cn(
        "flex flex-col gap-3 rounded-[var(--vpw-radius-xl)] border px-4 py-3 text-sm sm:flex-row sm:items-start sm:justify-between",
        toneClass[tone],
        className,
      )}
      role={tone === "critical" ? "alert" : "status"}
    >
      <div className="flex min-w-0 gap-3">
        <Icon aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0" />
        <div className="min-w-0">
          <p className="font-semibold">{title}</p>
          {children ? (
            <div className="mt-1 leading-5 text-[var(--vpw-text-secondary)]">
              {children}
            </div>
          ) : null}
        </div>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  )
}
