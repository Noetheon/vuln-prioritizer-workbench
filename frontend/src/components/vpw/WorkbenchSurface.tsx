import {
  isValidElement,
  type ComponentPropsWithoutRef,
  type ReactNode,
} from "react"

import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"

import {
  VpwDataTable,
  type VpwDataTableColumn,
  type VpwDataTableDensity,
  type VpwDataTableSort,
  type VpwDataTableVariant,
} from "./VpwDataTable"
import type { VpwEmptyStateProps } from "./VpwEmptyState"
import { VpwFilterBar, type VpwFilterBarProps } from "./VpwFilterBar"
import {
  VpwCompactMetric,
  type VpwCompactTone,
  VpwMetricStrip,
  VpwSection,
} from "./VpwLayout"
import { VpwSectionHeader } from "./VpwSectionHeader"
import { VpwSkeletonStack } from "./VpwSkeletonStack"
import { VpwTableCard } from "./VpwTableCard"
import {
  SignalBadge,
  type SignalBadgeProps,
  StatusBadge,
  type StatusBadgeProps,
} from "./WorkbenchBadges"
import { EmptyState } from "./WorkbenchFeedback"

export type PageHeaderProps = Omit<
  ComponentPropsWithoutRef<"header">,
  "title"
> & {
  actions?: ReactNode
  context?: ReactNode
  description?: ReactNode
  eyebrow?: ReactNode
  status?: ReactNode
  title: ReactNode
}

export function PageHeader({
  actions,
  className,
  context,
  description,
  eyebrow,
  status,
  title,
  ...props
}: PageHeaderProps) {
  return (
    <header
      className={cn(
        "flex min-w-0 flex-col gap-3 border-b border-[var(--vpw-border-subtle)] pb-4",
        className,
      )}
      {...props}
    >
      <div className="flex min-w-0 flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          {eyebrow ? <p className="vpw-label">{eyebrow}</p> : null}
          <h1 className="mt-1 text-2xl font-semibold leading-tight text-[var(--vpw-text-primary)]">
            {title}
          </h1>
          {description ? (
            <p className="mt-1 max-w-3xl text-sm leading-6 text-[var(--vpw-text-secondary)]">
              {description}
            </p>
          ) : null}
        </div>
        {actions || status ? (
          <div className="flex min-w-0 flex-wrap items-center gap-2 lg:justify-end">
            {status}
            {actions}
          </div>
        ) : null}
      </div>
      {context ? <div className="min-w-0">{context}</div> : null}
    </header>
  )
}

export type ContextBarItem = {
  label: string
  value: ReactNode
  description?: ReactNode
  id?: string
  signal?: SignalBadgeProps
  status?: StatusBadgeProps
}

export type ContextBarProps = Omit<
  ComponentPropsWithoutRef<"section">,
  "title"
> & {
  actions?: ReactNode
  description?: ReactNode
  items?: readonly ContextBarItem[]
  title?: ReactNode
}

export function ContextBar({
  actions,
  children,
  className,
  description,
  items = [],
  title,
  ...props
}: ContextBarProps) {
  return (
    <section
      aria-label={typeof title === "string" ? title : "Workbench context"}
      className={cn(
        "vpw-panel flex min-w-0 flex-col gap-3 p-[var(--vpw-panel-padding)]",
        className,
      )}
      {...props}
    >
      {title || description || actions ? (
        <div className="flex min-w-0 flex-col gap-3 md:flex-row md:items-start md:justify-between">
          <div className="min-w-0">
            {title ? (
              <h2 className="text-base font-semibold leading-tight text-[var(--vpw-text-primary)]">
                {title}
              </h2>
            ) : null}
            {description ? (
              <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--vpw-text-secondary)]">
                {description}
              </p>
            ) : null}
          </div>
          {actions ? (
            <div className="flex min-w-0 flex-wrap items-center gap-2 md:justify-end">
              {actions}
            </div>
          ) : null}
        </div>
      ) : null}
      {items.length > 0 ? (
        <div className="grid min-w-0 gap-2 md:grid-cols-2 xl:grid-cols-4">
          {items.map((item) => (
            <div
              className="min-w-0 border-t border-[var(--vpw-border-subtle)] pt-2 first:border-t-0 first:pt-0 md:first:border-t md:first:pt-2"
              key={item.id ?? item.label}
            >
              <p className="vpw-label">{item.label}</p>
              <div className="mt-1 flex min-w-0 flex-wrap items-center gap-2">
                <div className="min-w-0 text-sm font-medium leading-5 text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]">
                  {item.value}
                </div>
                {item.status ? <StatusBadge {...item.status} /> : null}
                {item.signal ? <SignalBadge {...item.signal} /> : null}
              </div>
              {item.description ? (
                <p className="mt-1 text-xs leading-5 text-[var(--vpw-text-muted)]">
                  {item.description}
                </p>
              ) : null}
            </div>
          ))}
        </div>
      ) : null}
      {children ? <div className="min-w-0">{children}</div> : null}
    </section>
  )
}

export type MetricStripMetric = {
  ariaLabel?: string
  label: string
  value: ReactNode
  description?: ReactNode
  icon?: ReactNode
  tone?: VpwCompactTone
  visualMaskValue?: boolean
}

export type MetricStripProps = Omit<
  ComponentPropsWithoutRef<"section">,
  "children"
> & {
  loading?: boolean
  loadingCardClassName?: string
  loadingCount?: number
  maxCardWidth?: string
  maxVisible?: 3 | 4 | 5
  metrics: readonly MetricStripMetric[]
  minCardWidth?: string
}

export function MetricStrip({
  className,
  loading = false,
  loadingCardClassName,
  loadingCount,
  maxCardWidth,
  maxVisible = 5,
  metrics,
  minCardWidth = "10rem",
  ...props
}: MetricStripProps) {
  const visibleMetrics = metrics.slice(0, maxVisible)
  const loadingSlotKeys = Array.from(
    { length: loadingCount ?? Math.max(visibleMetrics.length, 3) },
    (_, index) => `metric-loading-slot-${index + 1}`,
  )

  return (
    <VpwMetricStrip
      className={cn("workbench-metric-strip", className)}
      maxCardWidth={maxCardWidth}
      minCardWidth={minCardWidth}
      {...props}
    >
      {loading
        ? loadingSlotKeys.map((slotKey) => (
            <Skeleton
              className={cn("h-[4.5rem]", loadingCardClassName)}
              key={slotKey}
            />
          ))
        : visibleMetrics.map((metric) => (
            <VpwCompactMetric
              aria-label={metric.ariaLabel}
              description={metric.description}
              icon={metric.icon}
              key={metric.label}
              label={metric.label}
              tone={metric.tone}
              value={metric.value}
              visualMaskValue={metric.visualMaskValue}
            />
          ))}
    </VpwMetricStrip>
  )
}

export type PageSectionProps = Omit<
  ComponentPropsWithoutRef<"section">,
  "title"
> & {
  actions?: ReactNode
  bodyClassName?: string
  description?: ReactNode
  eyebrow?: string
  footer?: ReactNode
  title?: ReactNode
  titleLevel?: 2 | 3
}

export function PageSection({
  actions,
  bodyClassName,
  children,
  className,
  description,
  eyebrow,
  footer,
  title,
  titleLevel = 2,
  ...props
}: PageSectionProps) {
  return (
    <VpwSection className={cn("workbench-page-section", className)} {...props}>
      {title ? (
        <VpwSectionHeader
          actions={actions}
          description={description}
          eyebrow={eyebrow}
          title={title}
          titleLevel={titleLevel}
        />
      ) : actions ? (
        <div className="flex min-w-0 flex-wrap justify-end gap-2">
          {actions}
        </div>
      ) : null}
      <div className={cn("min-w-0", bodyClassName)}>{children}</div>
      {footer ? (
        <div className="min-w-0 border-t border-[var(--vpw-border-subtle)] pt-3">
          {footer}
        </div>
      ) : null}
    </VpwSection>
  )
}

export type FilterBarProps = VpwFilterBarProps & {
  resetAction?: ReactNode
  resultCount?: number | string
  resultLabel?: ReactNode
}

export function FilterBar({
  actions,
  resetAction,
  resultCount,
  resultLabel,
  ...props
}: FilterBarProps) {
  const resolvedActions =
    resultCount !== undefined || resultLabel || resetAction || actions ? (
      <>
        {resultCount !== undefined || resultLabel ? (
          <span className="vpw-label whitespace-nowrap">
            {resultLabel ?? `${resultCount} shown`}
          </span>
        ) : null}
        {resetAction}
        {actions}
      </>
    ) : undefined

  return <VpwFilterBar actions={resolvedActions} {...props} />
}

export type DataTableFrameEmptyStateConfig = Pick<
  VpwEmptyStateProps,
  "action" | "ariaLabel" | "description" | "icon" | "title"
>

export type DataTableFrameEmptyState =
  | ReactNode
  | DataTableFrameEmptyStateConfig

export type DataTableFrameProps<TData> = Omit<
  ComponentPropsWithoutRef<"div">,
  "title"
> & {
  actions?: ReactNode
  ariaLabel?: string
  bodyClassName?: string
  caption?: string
  columns: readonly VpwDataTableColumn<TData>[]
  data?: readonly TData[]
  density?: VpwDataTableDensity
  description?: ReactNode
  emptyState?: DataTableFrameEmptyState
  eyebrow?: string
  filters?: ReactNode
  footer?: ReactNode
  getRowClassName?: (row: TData, index: number) => string | undefined
  getRowKey: (row: TData, index: number) => string
  loading?: boolean
  loadingState?: ReactNode
  minWidth?: string
  mobileCards?: boolean
  pagination?: ReactNode
  rowClassName?: string
  tableClassName?: string
  title: ReactNode
  titleLevel?: 2 | 3
  variant?: VpwDataTableVariant
}

export function DataTableFrame<TData>({
  actions,
  ariaLabel,
  bodyClassName,
  caption,
  className,
  columns,
  data = [],
  density = "standard",
  description,
  emptyState,
  eyebrow,
  filters,
  footer,
  getRowClassName,
  getRowKey,
  loading = false,
  loadingState,
  minWidth,
  mobileCards = true,
  pagination,
  rowClassName,
  tableClassName,
  title,
  titleLevel = 2,
  variant = "default",
  ...props
}: DataTableFrameProps<TData>) {
  return (
    <VpwTableCard
      actions={actions}
      bodyClassName={cn("workbench-data-table-frame__body", bodyClassName)}
      className={cn("workbench-data-table-frame", className)}
      description={description}
      eyebrow={eyebrow}
      title={title}
      titleLevel={titleLevel}
      {...props}
    >
      {filters}
      {loading ? (
        (loadingState ?? <VpwSkeletonStack rows={5} />)
      ) : (
        <VpwDataTable
          ariaLabel={ariaLabel}
          caption={caption}
          columns={columns}
          data={data}
          density={density}
          emptyState={resolveEmptyState(emptyState)}
          getRowClassName={getRowClassName}
          getRowKey={getRowKey}
          minWidth={minWidth}
          mobileCards={mobileCards}
          rowClassName={rowClassName}
          tableClassName={tableClassName}
          variant={variant}
        />
      )}
      {pagination ? (
        <div className="flex min-w-0 flex-wrap items-center justify-between gap-2 border-t border-[var(--vpw-border-subtle)] pt-3">
          {pagination}
        </div>
      ) : null}
      {footer ? <div className="min-w-0">{footer}</div> : null}
    </VpwTableCard>
  )
}

function resolveEmptyState(emptyState: DataTableFrameEmptyState | undefined) {
  if (emptyState === undefined) {
    return (
      <EmptyState
        description="Adjust filters or import supplied evidence to populate this table."
        title="No records"
      />
    )
  }
  if (isEmptyStateConfig(emptyState)) {
    return <EmptyState {...emptyState} />
  }
  return emptyState as ReactNode
}

function isEmptyStateConfig(
  value: DataTableFrameEmptyState,
): value is DataTableFrameEmptyStateConfig {
  return (
    typeof value === "object" &&
    value !== null &&
    !isValidElement(value) &&
    "title" in value
  )
}

export type {
  VpwDataTableColumn as DataTableColumn,
  VpwDataTableDensity as DataTableDensity,
  VpwDataTableSort as DataTableSort,
  VpwDataTableVariant as DataTableVariant,
}
