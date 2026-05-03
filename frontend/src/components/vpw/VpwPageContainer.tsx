import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export type VpwPageContainerProps = {
  children: ReactNode
  className?: string
}

export function VpwPageContainer({
  children,
  className,
}: VpwPageContainerProps) {
  return (
    <div className={cn("vpw-page-container py-6", className)}>{children}</div>
  )
}
