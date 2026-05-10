import {
  AlertTriangle,
  CheckCircle2,
  Info,
  type LucideIcon,
  XCircle,
} from "lucide-react"
import type { ComponentPropsWithoutRef, ReactNode } from "react"

import { cn } from "@/lib/utils"

export type VpwStatusBannerTone = "info" | "success" | "warning" | "critical"
export type AlertVariant = "default" | "destructive"

export type AlertProps = ComponentPropsWithoutRef<"div"> & {
  variant?: AlertVariant
}

export type VpwStatusBannerProps = {
  title: string
  children?: ReactNode
  action?: ReactNode
  className?: string
  tone?: VpwStatusBannerTone
}

const alertVariantClass: Record<AlertVariant, string> = {
  default: "border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)]",
  destructive:
    "border-[color-mix(in_srgb,var(--vpw-red)_28%,var(--vpw-bg-card))] bg-[var(--vpw-bg-critical)] text-[color-mix(in_srgb,var(--vpw-red)_65%,var(--vpw-text-primary))]",
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

export function Alert({
  className,
  role = "alert",
  variant = "default",
  ...props
}: AlertProps) {
  return (
    <div
      data-slot="alert"
      role={role}
      className={cn(
        "relative w-full rounded-[var(--vpw-radius-xl)] border px-4 py-3 text-sm",
        alertVariantClass[variant],
        className,
      )}
      {...props}
    />
  )
}

export function AlertTitle({
  className,
  ...props
}: ComponentPropsWithoutRef<"div">) {
  return (
    <div
      data-slot="alert-title"
      className={cn("font-semibold leading-5", className)}
      {...props}
    />
  )
}

export function AlertDescription({
  className,
  ...props
}: ComponentPropsWithoutRef<"div">) {
  return (
    <div
      data-slot="alert-description"
      className={cn(
        "leading-5 text-[var(--vpw-text-secondary)] [&_p]:leading-6",
        className,
      )}
      {...props}
    />
  )
}

export function AlertAction({
  className,
  ...props
}: ComponentPropsWithoutRef<"div">) {
  return (
    <div
      data-slot="alert-action"
      className={cn("shrink-0", className)}
      {...props}
    />
  )
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
    <Alert
      className={cn(
        "flex flex-col gap-3 rounded-[var(--vpw-radius-xl)] border px-4 py-3 text-sm sm:flex-row sm:items-start sm:justify-between",
        toneClass[tone],
        className,
      )}
      role={tone === "critical" ? "alert" : "status"}
      variant={tone === "critical" ? "destructive" : "default"}
    >
      <div className="flex min-w-0 gap-3">
        <Icon aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
        <div className="min-w-0">
          <AlertTitle>{title}</AlertTitle>
          {children ? (
            <AlertDescription className="mt-1">{children}</AlertDescription>
          ) : null}
        </div>
      </div>
      {action ? <AlertAction>{action}</AlertAction> : null}
    </Alert>
  )
}
