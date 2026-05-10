import { Download, FileText } from "lucide-react"
import type { ReactNode } from "react"

import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { cn } from "@/lib/utils"

import { VpwBadge } from "./VpwBadge"

export type VpwEvidenceArtifactCardProps = {
  title: string
  format: string
  audience: string
  description: string
  actionLabel: string
  actionType?: "button" | "submit" | "reset"
  busy?: boolean
  className?: string
  disabled?: boolean
  icon?: ReactNode
  onAction?: () => void
}

export function VpwEvidenceArtifactCard({
  actionLabel,
  actionType = "button",
  audience,
  busy = false,
  className,
  description,
  disabled = false,
  format,
  icon,
  onAction,
  title,
}: VpwEvidenceArtifactCardProps) {
  return (
    <Card className={cn("vpw-card h-full gap-4 py-0", className)}>
      <CardHeader className="flex-row items-start gap-3 pb-0 pt-6">
        <div className="rounded-[var(--vpw-radius-lg)] bg-[var(--vpw-bg-panel)] p-2 text-[var(--vpw-text-secondary)]">
          {icon ?? <FileText className="size-4" aria-hidden="true" />}
        </div>
        <div className="min-w-0">
          <CardTitle className="text-base">{title}</CardTitle>
          <div className="mt-2 flex flex-wrap gap-1.5">
            <VpwBadge>{format}</VpwBadge>
            <VpwBadge tone="info">{audience}</VpwBadge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col gap-4 pb-6">
        <CardDescription className="min-h-11 text-sm leading-5 text-[var(--vpw-text-secondary)]">
          {description}
        </CardDescription>
        <Button
          aria-busy={busy}
          className="mt-auto w-full"
          disabled={disabled}
          onClick={onAction}
          type={actionType}
          variant="outline"
        >
          <Download aria-hidden="true" data-icon="inline-start" />
          {actionLabel}
        </Button>
      </CardContent>
    </Card>
  )
}
