import { Search } from "lucide-react"
import type { ComponentPropsWithoutRef, ReactNode } from "react"

import { cn } from "@/lib/utils"

export type EmptyMediaVariant = "default" | "icon"

export type VpwEmptyStateProps = {
  title: string
  ariaLabel?: string
  description?: string
  action?: ReactNode
  className?: string
  icon?: ReactNode
}

const emptyMediaVariantClass: Record<EmptyMediaVariant, string> = {
  default: "bg-transparent",
  icon: "rounded-[var(--vpw-radius-lg)] bg-[var(--vpw-bg-panel)] p-3 text-[var(--vpw-text-muted)]",
}

export function Empty({
  className,
  ...props
}: ComponentPropsWithoutRef<"section">) {
  return (
    <section
      data-slot="empty"
      className={cn("vpw-empty-state", className)}
      {...props}
    />
  )
}

export function EmptyHeader({
  className,
  ...props
}: ComponentPropsWithoutRef<"div">) {
  return (
    <div
      data-slot="empty-header"
      className={cn(
        "mx-auto flex max-w-md flex-col items-center gap-2 text-center",
        className,
      )}
      {...props}
    />
  )
}

export function EmptyMedia({
  className,
  variant = "default",
  ...props
}: ComponentPropsWithoutRef<"div"> & {
  variant?: EmptyMediaVariant
}) {
  return (
    <div
      data-slot="empty-media"
      data-variant={variant}
      className={cn(
        "mb-2 flex shrink-0 items-center justify-center",
        emptyMediaVariantClass[variant],
        className,
      )}
      {...props}
    />
  )
}

export function EmptyTitle({
  className,
  ...props
}: ComponentPropsWithoutRef<"h3">) {
  return (
    <h3
      data-slot="empty-title"
      className={cn(
        "text-base font-semibold text-[var(--vpw-text-primary)]",
        className,
      )}
      {...props}
    />
  )
}

export function EmptyDescription({
  className,
  ...props
}: ComponentPropsWithoutRef<"p">) {
  return (
    <p
      data-slot="empty-description"
      className={cn(
        "text-sm leading-6 text-[var(--vpw-text-secondary)]",
        className,
      )}
      {...props}
    />
  )
}

export function EmptyContent({
  className,
  ...props
}: ComponentPropsWithoutRef<"div">) {
  return (
    <div
      data-slot="empty-content"
      className={cn("flex w-full justify-center pt-3", className)}
      {...props}
    />
  )
}

export function VpwEmptyState({
  action,
  ariaLabel,
  className,
  description,
  icon,
  title,
}: VpwEmptyStateProps) {
  return (
    <Empty aria-label={ariaLabel} className={className}>
      <EmptyHeader>
        <EmptyMedia variant="icon">
          {icon ?? <Search className="size-5" aria-hidden="true" />}
        </EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        {description ? (
          <EmptyDescription>{description}</EmptyDescription>
        ) : null}
      </EmptyHeader>
      {action ? <EmptyContent>{action}</EmptyContent> : null}
    </Empty>
  )
}
