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

export type VpwPanelProps = {
  children: ReactNode
  className?: string
  padded?: boolean
}

const gridClass: Record<NonNullable<VpwGridProps["columns"]>, string> = {
  1: "grid-cols-1",
  2: "grid-cols-1 lg:grid-cols-2",
  3: "grid-cols-1 md:grid-cols-2 xl:grid-cols-3",
  4: "grid-cols-1 sm:grid-cols-2 xl:grid-cols-4",
}

export function VpwSection({ children, className, ...props }: VpwSectionProps) {
  return (
    <section className={cn("space-y-4", className)} {...props}>
      {children}
    </section>
  )
}

export function VpwGrid({ children, className, columns = 3 }: VpwGridProps) {
  return (
    <div className={cn("grid gap-4", gridClass[columns], className)}>
      {children}
    </div>
  )
}

export function VpwPanel({
  children,
  className,
  padded = true,
}: VpwPanelProps) {
  return (
    <div className={cn("vpw-panel", padded && "p-5", className)}>
      {children}
    </div>
  )
}
