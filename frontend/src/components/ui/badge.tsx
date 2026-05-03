import { cva, type VariantProps } from "class-variance-authority"
import type * as React from "react"

import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex w-fit shrink-0 items-center justify-center whitespace-nowrap rounded-[var(--vpw-radius-pill)] border px-2 py-0.5 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default:
          "border-transparent bg-[var(--vpw-blue)] text-primary-foreground hover:bg-[var(--vpw-blue)]/90",
        secondary:
          "border-transparent bg-[var(--vpw-bg-panel)] text-[var(--vpw-text-secondary)] hover:bg-[var(--vpw-bg-panel)]",
        destructive:
          "border-transparent bg-[var(--vpw-red)] text-destructive-foreground hover:bg-[var(--vpw-red)]/90",
        outline:
          "border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] text-[var(--vpw-text-secondary)]",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

export { Badge, badgeVariants }
