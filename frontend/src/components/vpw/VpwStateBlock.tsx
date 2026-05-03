import {
  AlertTriangle,
  CheckCircle2,
  Loader2,
  type LucideIcon,
  Search,
  XCircle,
} from "lucide-react"
import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export type VpwStateBlockTone =
  | "empty"
  | "loading"
  | "success"
  | "warning"
  | "critical"

export type VpwStateBlockProps = {
  title: string
  action?: ReactNode
  children?: ReactNode
  className?: string
  tone?: VpwStateBlockTone
}

const iconByTone: Record<VpwStateBlockTone, LucideIcon> = {
  empty: Search,
  loading: Loader2,
  success: CheckCircle2,
  warning: AlertTriangle,
  critical: XCircle,
}

const toneClass: Record<VpwStateBlockTone, string> = {
  empty: "bg-[var(--vpw-bg-card)] text-[var(--vpw-text-muted)]",
  loading: "bg-[var(--vpw-bg-panel)] text-[var(--vpw-text-muted)]",
  success: "bg-[var(--vpw-bg-success)] text-[var(--vpw-green)]",
  warning: "bg-[var(--vpw-bg-warning)] text-[var(--vpw-amber)]",
  critical: "bg-[var(--vpw-bg-critical)] text-[var(--vpw-red)]",
}

export function VpwStateBlock({
  action,
  children,
  className,
  title,
  tone = "empty",
}: VpwStateBlockProps) {
  const Icon = iconByTone[tone]

  return (
    <div
      className={cn(
        "grid min-h-48 place-items-center rounded-[var(--vpw-radius-xl)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-6 text-center",
        className,
      )}
    >
      <div className="max-w-md">
        <div
          className={cn(
            "mx-auto grid size-11 place-items-center rounded-[var(--vpw-radius-lg)]",
            toneClass[tone],
          )}
        >
          <Icon
            aria-hidden="true"
            className={cn("h-5 w-5", tone === "loading" && "animate-spin")}
          />
        </div>
        <h3 className="mt-4 text-base font-semibold text-[var(--vpw-text-primary)]">
          {title}
        </h3>
        {children ? (
          <div className="mt-2 text-sm leading-6 text-[var(--vpw-text-secondary)]">
            {children}
          </div>
        ) : null}
        {action ? <div className="mt-5">{action}</div> : null}
      </div>
    </div>
  )
}
