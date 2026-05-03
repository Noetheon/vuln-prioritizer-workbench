import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { cn } from "@/lib/utils"

import { VpwBadge, type VpwBadgeTone } from "./VpwBadge"

export type VpwExecutiveDecisionSummaryProps = {
  problem: string
  businessImpact: string
  recommendation: string
  priority: string
  decisionStatement: string
  className?: string
  demo?: boolean
  priorityTone?: VpwBadgeTone
}

export function VpwExecutiveDecisionSummary({
  businessImpact,
  className,
  decisionStatement,
  demo = false,
  priority,
  priorityTone = "critical",
  problem,
  recommendation,
}: VpwExecutiveDecisionSummaryProps) {
  return (
    <Card className={cn("vpw-card py-0", className)}>
      <CardHeader className="flex-row items-start justify-between gap-4 pb-3 pt-6">
        <div>
          <CardTitle className="text-lg">Executive Decision Summary</CardTitle>
          <CardDescription>
            Risk translated to business language for CISO review
          </CardDescription>
        </div>
        {demo ? <VpwBadge tone="warning">Demo preview</VpwBadge> : null}
      </CardHeader>
      <CardContent className="space-y-4 pb-6">
        <div className="grid gap-3 lg:grid-cols-2">
          <SummaryBlock label="Problem" value={problem} />
          <SummaryBlock label="Business impact" value={businessImpact} />
          <SummaryBlock label="Recommendation" value={recommendation} />
          <SummaryBlock
            label="Priority"
            value={priority}
            valueTone={priorityTone}
          />
        </div>
        <p className="rounded-[var(--vpw-radius-lg)] bg-[var(--vpw-bg-panel)] px-4 py-3 text-sm leading-6 text-[var(--vpw-text-secondary)]">
          <span className="font-semibold text-[var(--vpw-text-primary)]">
            Decision statement:{" "}
          </span>
          {decisionStatement}
        </p>
      </CardContent>
    </Card>
  )
}

function SummaryBlock({
  label,
  value,
  valueTone,
}: {
  label: string
  value: string
  valueTone?: VpwBadgeTone
}) {
  return (
    <div className="vpw-panel bg-[var(--vpw-bg-card)] p-4">
      <p className="vpw-label">{label}</p>
      {valueTone ? (
        <div className="mt-2">
          <VpwBadge tone={valueTone}>{value}</VpwBadge>
        </div>
      ) : (
        <p className="mt-1 text-sm leading-6 text-[var(--vpw-text-secondary)]">
          {value}
        </p>
      )}
    </div>
  )
}
