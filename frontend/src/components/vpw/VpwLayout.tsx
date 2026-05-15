import type { ComponentPropsWithoutRef, ReactNode } from "react"

import { cn } from "@/lib/utils"

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

const gridClass: Record<NonNullable<VpwGridProps["columns"]>, string> = {
  1: "grid-cols-1",
  2: "grid-cols-1 lg:grid-cols-2",
  3: "grid-cols-1 md:grid-cols-2 xl:grid-cols-3",
  4: "grid-cols-1 sm:grid-cols-2 xl:grid-cols-4",
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
      className={cn("grid min-w-0 gap-4 [&>*]:min-w-0", gridClass[columns], className)}
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
