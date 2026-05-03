import { Download, FileText } from "lucide-react"
import type { ReactNode } from "react"

import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { cn } from "@/lib/utils"

import { VpwBadge } from "./VpwBadge"

export type VpwEvidenceArtifactCardProps = {
  title: string
  format: string
  audience: string
  description: string
  actionLabel: string
  actionType?: "button" | "submit" | "reset"
  className?: string
  disabled?: boolean
  icon?: ReactNode
  onAction?: () => void
}

export function VpwEvidenceArtifactCard({
  actionLabel,
  actionType = "button",
  audience,
  className,
  description,
  disabled = false,
  format,
  icon,
  onAction,
  title,
}: VpwEvidenceArtifactCardProps) {
  return (
    <Card className={cn("vpw-card h-full py-0", className)}>
      <CardContent className="flex h-full flex-col gap-4 p-6">
        <div className="flex items-start gap-3">
          <div className="rounded-[var(--vpw-radius-lg)] bg-[var(--vpw-bg-panel)] p-2 text-[var(--vpw-text-secondary)]">
            {icon ?? <FileText className="h-4 w-4" aria-hidden="true" />}
          </div>
          <div className="min-w-0">
            <h3 className="text-base font-semibold text-[var(--vpw-text-primary)]">
              {title}
            </h3>
            <div className="mt-2 flex flex-wrap gap-1.5">
              <VpwBadge>{format}</VpwBadge>
              <VpwBadge tone="info">{audience}</VpwBadge>
            </div>
          </div>
        </div>
        <p className="min-h-11 text-sm leading-5 text-[var(--vpw-text-secondary)]">
          {description}
        </p>
        <Button
          className="mt-auto w-full"
          disabled={disabled}
          onClick={onAction}
          type={actionType}
          variant="outline"
        >
          <Download className="h-4 w-4" aria-hidden="true" />
          {actionLabel}
        </Button>
      </CardContent>
    </Card>
  )
}
