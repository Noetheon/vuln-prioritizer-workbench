import { FileInput, GitBranch, History, PackageCheck } from "lucide-react"
import type { ReactNode } from "react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { cn } from "@/lib/utils"

import { VpwBadge, type VpwBadgeTone } from "./VpwBadge"
import { VpwDataTable, type VpwDataTableColumn } from "./VpwDataTable"
import { VpwTimeline, type VpwTimelineItem } from "./VpwTimeline"

export type VpwImportStepCardProps = {
  title: string
  description: string
  status: string
  className?: string
  statusTone?: VpwBadgeTone
}

export type VpwReportHistoryRow = {
  artifact: string
  format: string
  generated: string
  status: string
}

export type VpwReportHistoryCardProps = {
  rows: readonly VpwReportHistoryRow[]
  className?: string
}

export type VpwProviderSnapshotCardProps = {
  sources: readonly { name: string; status: string; tone?: VpwBadgeTone }[]
  action?: ReactNode
  className?: string
  onRefresh?: () => void
  refreshLabel?: string
  snapshotId?: string
}

export type VpwEvidenceFlowCardProps = {
  items: readonly VpwTimelineItem[]
  className?: string
}

const reportColumns: VpwDataTableColumn<VpwReportHistoryRow>[] = [
  { id: "artifact", header: "Artifact", cell: (row) => row.artifact },
  {
    id: "format",
    header: "Format",
    cell: (row) => <VpwBadge tone="info">{row.format}</VpwBadge>,
  },
  { id: "generated", header: "Generated", cell: (row) => row.generated },
  {
    id: "status",
    header: "Status",
    cell: (row) => <VpwBadge tone="success">{row.status}</VpwBadge>,
  },
]

export function VpwImportStepCard({
  className,
  description,
  status,
  statusTone = "info",
  title,
}: VpwImportStepCardProps) {
  return (
    <Card className={cn("vpw-card py-0", className)}>
      <CardContent className="flex items-start gap-4 p-5">
        <div className="rounded-[var(--vpw-radius-lg)] bg-[var(--vpw-bg-info)] p-2 text-[var(--vpw-blue)]">
          <FileInput aria-hidden="true" className="h-4 w-4" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-start justify-between gap-3">
            <h3 className="font-semibold text-[var(--vpw-text-primary)]">
              {title}
            </h3>
            <VpwBadge tone={statusTone}>{status}</VpwBadge>
          </div>
          <p className="mt-1 text-sm leading-6 text-[var(--vpw-text-secondary)]">
            {description}
          </p>
        </div>
      </CardContent>
    </Card>
  )
}

export function VpwReportHistoryCard({
  className,
  rows,
}: VpwReportHistoryCardProps) {
  return (
    <Card className={cn("vpw-card py-0", className)}>
      <CardHeader className="pb-3 pt-5">
        <CardTitle className="flex items-center gap-2 text-base">
          <History aria-hidden="true" className="h-4 w-4" />
          Report History
        </CardTitle>
      </CardHeader>
      <CardContent className="pb-5">
        <VpwDataTable
          caption="Report history"
          columns={reportColumns}
          data={rows}
          density="compact"
          getRowKey={(row) => `${row.artifact}-${row.generated}`}
        />
      </CardContent>
    </Card>
  )
}

export function VpwProviderSnapshotCard({
  action,
  className,
  onRefresh,
  refreshLabel = "Refresh snapshot",
  snapshotId = "snapshot-local",
  sources,
}: VpwProviderSnapshotCardProps) {
  return (
    <Card className={cn("vpw-card py-0", className)}>
      <CardHeader className="pb-3 pt-5">
        <CardTitle className="flex items-center gap-2 text-base">
          <PackageCheck aria-hidden="true" className="h-4 w-4" />
          Provider Snapshot
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 pb-5">
        <p className="font-mono text-xs text-[var(--vpw-text-muted)]">
          {snapshotId}
        </p>
        <div className="flex flex-wrap gap-2">
          {sources.map((source) => (
            <VpwBadge key={source.name} tone={source.tone ?? "success"}>
              {source.name}: {source.status}
            </VpwBadge>
          ))}
        </div>
        {action ??
          (onRefresh ? (
            <Button
              className="w-full"
              onClick={onRefresh}
              type="button"
              variant="outline"
            >
              {refreshLabel}
            </Button>
          ) : null)}
      </CardContent>
    </Card>
  )
}

export function VpwEvidenceFlowCard({
  className,
  items,
}: VpwEvidenceFlowCardProps) {
  return (
    <Card className={cn("vpw-card py-0", className)}>
      <CardHeader className="pb-3 pt-5">
        <CardTitle className="flex items-center gap-2 text-base">
          <GitBranch aria-hidden="true" className="h-4 w-4" />
          Evidence Flow
        </CardTitle>
      </CardHeader>
      <CardContent className="pb-5">
        <VpwTimeline items={items} />
      </CardContent>
    </Card>
  )
}
