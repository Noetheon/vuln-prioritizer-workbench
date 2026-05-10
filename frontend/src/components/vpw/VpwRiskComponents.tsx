import { AlertTriangle, Server, ShieldCheck } from "lucide-react"
import type { ReactNode } from "react"

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { cn } from "@/lib/utils"

import { VpwBadge, type VpwBadgeTone } from "./VpwBadge"
import { type VpwKeyValueItem, VpwKeyValueList } from "./VpwKeyValueList"
import { VpwProgress } from "./VpwProgress"

export type VpwFindingSummaryCardProps = {
  cveId: string
  title: string
  className?: string
  priority: string
  priorityTone?: VpwBadgeTone
  signals: readonly string[]
}

export type VpwAssetContextCardProps = {
  asset: string
  businessService: string
  className?: string
  criticality: string
  exposure: string
  owner: string
}

export type VpwWaiverDecisionCardProps = {
  owner: string
  reason: string
  reviewDate: string
  status: string
  className?: string
  statusTone?: VpwBadgeTone
}

export type VpwAttackTechniqueCardProps = {
  technique: string
  tactic: string
  className?: string
  confidence?: string
  description?: ReactNode
}

export function VpwFindingSummaryCard({
  className,
  cveId,
  priority,
  priorityTone = "critical",
  signals,
  title,
}: VpwFindingSummaryCardProps) {
  return (
    <Card className={cn("vpw-card py-0", className)}>
      <CardHeader className="pb-3 pt-5">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <CardDescription className="font-mono text-xs">
              {cveId}
            </CardDescription>
            <CardTitle className="mt-1 text-base">{title}</CardTitle>
          </div>
          <VpwBadge tone={priorityTone}>{priority}</VpwBadge>
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 pb-5">
        <div className="flex flex-wrap gap-2">
          {signals.map((signal) => (
            <VpwBadge key={signal} tone="info">
              {signal}
            </VpwBadge>
          ))}
        </div>
        <VpwProgress label="Risk score" tone={priorityTone} value={92} />
      </CardContent>
    </Card>
  )
}

export function VpwAssetContextCard({
  asset,
  businessService,
  className,
  criticality,
  exposure,
  owner,
}: VpwAssetContextCardProps) {
  const items: VpwKeyValueItem[] = [
    { label: "Asset", value: asset },
    { label: "Owner", value: owner },
    { label: "Service", value: businessService },
    { label: "Criticality", value: criticality, tone: "warning" },
    { label: "Exposure", value: exposure, tone: "critical" },
  ]

  return (
    <Card className={cn("vpw-card py-0", className)}>
      <CardHeader className="pb-3 pt-5">
        <CardTitle className="flex items-center gap-2 text-base">
          <Server aria-hidden="true" className="size-4" />
          Asset Context
        </CardTitle>
      </CardHeader>
      <CardContent className="pb-5">
        <VpwKeyValueList items={items} />
      </CardContent>
    </Card>
  )
}

export function VpwWaiverDecisionCard({
  className,
  owner,
  reason,
  reviewDate,
  status,
  statusTone = "warning",
}: VpwWaiverDecisionCardProps) {
  return (
    <Card className={cn("vpw-card py-0", className)}>
      <CardHeader className="pb-3 pt-5">
        <CardTitle className="flex items-center justify-between gap-3 text-base">
          Risk Acceptance
          <VpwBadge tone={statusTone}>{status}</VpwBadge>
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 pb-5 text-sm">
        <p className="leading-6 text-[var(--vpw-text-secondary)]">{reason}</p>
        <VpwKeyValueList
          columns={2}
          items={[
            { label: "Owner", value: owner },
            { label: "Review", value: reviewDate },
          ]}
        />
      </CardContent>
    </Card>
  )
}

export function VpwAttackTechniqueCard({
  className,
  confidence = "Reviewed",
  description,
  tactic,
  technique,
}: VpwAttackTechniqueCardProps) {
  return (
    <Card className={cn("vpw-card py-0", className)}>
      <CardHeader className="pb-3 pt-5">
        <CardTitle className="flex items-start gap-2 text-base">
          <ShieldCheck aria-hidden="true" className="mt-0.5 size-4" />
          <span>{technique}</span>
        </CardTitle>
        <CardDescription className="pl-6 text-sm">{tactic}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 pb-5">
        <VpwBadge tone="support">{confidence}</VpwBadge>
        {description ? (
          <div className="text-sm leading-6 text-[var(--vpw-text-secondary)]">
            {description}
          </div>
        ) : (
          <div className="flex items-start gap-2 rounded-[var(--vpw-radius-lg)] bg-[var(--vpw-bg-warning)] p-3 text-sm text-[var(--vpw-text-secondary)]">
            <AlertTriangle
              aria-hidden="true"
              className="mt-0.5 size-4 shrink-0 text-[var(--vpw-amber)]"
            />
            No heuristic mapping is inferred. Use reviewed mappings only.
          </div>
        )}
      </CardContent>
    </Card>
  )
}
