import { Search } from "lucide-react"
import type { ComponentPropsWithoutRef } from "react"

import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"

export type VpwSearchInputProps = Omit<
  ComponentPropsWithoutRef<typeof Input>,
  "type"
>

export function VpwSearchInput({ className, ...props }: VpwSearchInputProps) {
  return (
    <div className={cn("vpw-search-control", className)}>
      <Search aria-hidden="true" className="vpw-search-control__icon" />
      <Input
        className="vpw-search-control__input !pl-9"
        type="search"
        {...props}
      />
    </div>
  )
}
