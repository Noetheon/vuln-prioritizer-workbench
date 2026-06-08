import type { CSSProperties, ComponentPropsWithoutRef, ReactNode } from "react"

import { cn } from "@/lib/utils"
import { VpwSectionHeader } from "./VpwSectionHeader"

export type VpwPageStackProps = ComponentPropsWithoutRef<"div"> & {
  children: ReactNode
  density?: "default" | "compact"
}

export type VpwSectionProps = ComponentPropsWithoutRef<"section"> & {
  children: ReactNode
}

export type VpwGridProps = {
  children: ReactNode
  className?: string
  columns?: 1 | 2 | 3 | 4
}

export type VpwPanelProps = ComponentPropsWithoutRef<"div"> & {
  children: ReactNode
  padded?: boolean
}

export type VpwSurfaceProps = ComponentPropsWithoutRef<"div"> & {
  children: ReactNode
}

export type VpwCompactTone =
  | "neutral"
  | "success"
  | "warning"
  | "critical"
  | "info"
  | "support"

export type VpwCommandPanelProps = Omit<VpwPanelProps, "children" | "title"> & {
  actions?: ReactNode
  children?: ReactNode
  description?: ReactNode
  eyebrow?: string
  note?: ReactNode
  title: ReactNode
}

export type VpwMetricStripProps = ComponentPropsWithoutRef<"section"> & {
  children: ReactNode
  maxCardWidth?: string
  minCardWidth?: string
}

export type VpwCompactMetricProps = ComponentPropsWithoutRef<"div"> & {
  description?: ReactNode
  icon?: ReactNode
  label: string
  tone?: VpwCompactTone
  value: ReactNode
  visualMaskValue?: boolean
}

const gridClass: Record<NonNullable<VpwGridProps["columns"]>, string> = {
  1: "grid-cols-1",
  2: "grid-cols-1 lg:grid-cols-2",
  3: "grid-cols-1 md:grid-cols-2 xl:grid-cols-3",
  4: "grid-cols-1 sm:grid-cols-2 xl:grid-cols-4",
}

export function VpwPageStack({
  children,
  className,
  density = "default",
  ...props
}: VpwPageStackProps) {
  return (
    <div
      className={cn(
        "vpw-page-stack",
        density === "compact" && "vpw-page-stack--compact",
        className,
      )}
      data-density={density}
      {...props}
    >
      {children}
    </div>
  )
}

export function VpwSection({ children, className, ...props }: VpwSectionProps) {
  return (
    <section className={cn("flex flex-col gap-4", className)} {...props}>
      {children}
    </section>
  )
}

export function VpwGrid({ children, className, columns = 3 }: VpwGridProps) {
  return (
    <div
      className={cn(
        "grid min-w-0 gap-4 [&>*]:min-w-0",
        gridClass[columns],
        className,
      )}
    >
      {children}
    </div>
  )
}

export function VpwPanel({
  children,
  className,
  padded = true,
  ...props
}: VpwPanelProps) {
  return (
    <div
      className={cn(
        "vpw-panel",
        padded && "p-[var(--vpw-panel-padding)]",
        className,
      )}
      {...props}
    >
      {children}
    </div>
  )
}

export function VpwSurface({ children, className, ...props }: VpwSurfaceProps) {
  return (
    <VpwPanel
      className={cn(
        "flex flex-col gap-[var(--vpw-surface-gap)] py-[var(--vpw-surface-padding-block)]",
        className,
      )}
      padded={false}
      {...props}
    >
      {children}
    </VpwPanel>
  )
}

export function VpwSurfaceHeader({
  children,
  className,
  ...props
}: VpwSurfaceProps) {
  return (
    <div
      className={cn(
        "flex flex-col gap-1.5 px-[var(--vpw-surface-padding-inline)]",
        className,
      )}
      {...props}
    >
      {children}
    </div>
  )
}

export function VpwSurfaceTitle({
  children,
  className,
  ...props
}: VpwSurfaceProps) {
  return (
    <div
      className={cn(
        "font-semibold leading-none text-[var(--vpw-text-primary)]",
        className,
      )}
      {...props}
    >
      {children}
    </div>
  )
}

export function VpwSurfaceDescription({
  children,
  className,
  ...props
}: VpwSurfaceProps) {
  return (
    <div
      className={cn("text-sm text-[var(--vpw-text-secondary)]", className)}
      {...props}
    >
      {children}
    </div>
  )
}

export function VpwSurfaceBody({
  children,
  className,
  ...props
}: VpwSurfaceProps) {
  return (
    <div
      className={cn("px-[var(--vpw-surface-padding-inline)]", className)}
      {...props}
    >
      {children}
    </div>
  )
}

export function VpwCommandPanel({
  actions,
  children,
  className,
  description,
  eyebrow,
  note,
  title,
  ...props
}: VpwCommandPanelProps) {
  const hasBody =
    children !== undefined && children !== null && children !== false

  return (
    <VpwPanel className={cn("vpw-command-panel", className)} {...props}>
      <div className="vpw-command-panel__header">
        <VpwSectionHeader
          className="vpw-command-panel__copy"
          description={description}
          eyebrow={eyebrow}
          title={title}
          titleLevel={2}
        />
        {actions ? (
          <div className="vpw-command-panel__actions">{actions}</div>
        ) : null}
      </div>
      {hasBody ? (
        <div className="vpw-command-panel__body">{children}</div>
      ) : null}
      {note ? <p className="vpw-command-panel__note">{note}</p> : null}
    </VpwPanel>
  )
}

export function VpwMetricStrip({
  children,
  className,
  maxCardWidth = "none",
  minCardWidth = "12rem",
  style,
  ...props
}: VpwMetricStripProps) {
  return (
    <section
      className={cn("vpw-metric-strip", className)}
      style={
        {
          "--vpw-metric-strip-max": maxCardWidth,
          "--vpw-metric-strip-min": minCardWidth,
          ...style,
        } as CSSProperties
      }
      {...props}
    >
      {children}
    </section>
  )
}

export function VpwCompactMetric({
  className,
  description,
  icon,
  label,
  tone = "neutral",
  value,
  visualMaskValue = false,
  ...props
}: VpwCompactMetricProps) {
  return (
    <div
      className={cn(
        "vpw-compact-metric",
        !icon && "vpw-compact-metric--plain",
        className,
      )}
      data-tone={tone}
      {...props}
    >
      {icon ? <span className="vpw-compact-metric__icon">{icon}</span> : null}
      <div className="vpw-compact-metric__body">
        <span className="vpw-label">{label}</span>
        <strong
          className={visualMaskValue ? "inline-block min-w-[7.5rem]" : undefined}
          data-vpw-visual-mask={visualMaskValue ? "true" : undefined}
        >
          {value}
        </strong>
        {description ? <small>{description}</small> : null}
      </div>
    </div>
  )
}
