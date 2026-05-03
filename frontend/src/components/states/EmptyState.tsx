import type { ReactNode } from "react"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { cn } from "@/lib/utils"

type EmptyStateProps = {
  action?: ReactNode
  ariaLabel: string
  compact?: boolean
  detail: ReactNode
  title: ReactNode
  className?: string
}

export function EmptyState({
  action,
  ariaLabel,
  compact = false,
  detail,
  title,
  className,
}: EmptyStateProps) {
  return (
    <Card
      aria-label={ariaLabel}
      className={cn("border-dashed", compact ? "py-4" : "py-8", className)}
    >
      <CardHeader className={cn("text-center", compact && "pb-2")}>
        <CardTitle className={cn("text-lg", compact && "text-base")}>
          {title}
        </CardTitle>
        <CardDescription
          className={cn("mx-auto max-w-md", compact && "text-sm")}
        >
          {detail}
        </CardDescription>
      </CardHeader>
      {action && (
        <CardContent className="flex justify-center pt-2">{action}</CardContent>
      )}
    </Card>
  )
}
