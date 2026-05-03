import type * as React from "react"

import { cn } from "@/lib/utils"

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "h-9 w-full min-w-0 rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] px-3 py-1 text-base text-[var(--vpw-text-primary)] shadow-[var(--vpw-shadow-1)] outline-none transition-colors placeholder:text-[var(--vpw-text-muted)] focus-visible:ring-2 focus-visible:ring-ring/50 disabled:opacity-50",
        className,
      )}
      {...props}
    />
  )
}

export { Input }
