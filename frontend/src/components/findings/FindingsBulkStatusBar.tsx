import type { FindingStatus } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { selectedCountLabel } from "@/lib/finding-bulk-selection"
import { manualStatusOptions } from "@/lib/finding-status-transitions"
import { cn } from "@/lib/utils"

export function FindingsBulkStatusBar({
  count,
  error,
  message,
  onChooseStatus,
  onClear,
  pending,
}: {
  count: number
  error: string
  message: string
  onChooseStatus: (status: FindingStatus) => void
  onClear: () => void
  pending: boolean
}) {
  if (count === 0 && !message && !error) return null
  return (
    <section
      aria-label="Bulk status change"
      className={cn(
        "flex flex-wrap items-center gap-3 rounded-lg border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-4 py-3",
        // Stays at the bottom of the screen while rows are chosen, so the
        // choice is visible wherever in the list it was made.
        count > 0 && "findings-bulk-bar--sticky",
      )}
    >
      {count > 0 ? (
        <>
          <strong className="text-sm">{selectedCountLabel(count)}</strong>
          <Select
            disabled={pending}
            onValueChange={(value) => onChooseStatus(value as FindingStatus)}
            value=""
          >
            <SelectTrigger
              aria-label="Set status for selected findings"
              className="h-9 w-48 bg-[var(--vpw-bg-card)] text-sm"
            >
              <SelectValue placeholder="Set status…" />
            </SelectTrigger>
            <SelectContent>
              {manualStatusOptions.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button
            disabled={pending}
            onClick={onClear}
            size="sm"
            type="button"
            variant="outline"
          >
            Clear selection
          </Button>
        </>
      ) : null}
      {message ? (
        <p className="text-sm" role="status">
          {message}
        </p>
      ) : null}
      {error ? (
        <p className="text-sm text-[var(--vpw-red)]" role="alert">
          {error}
        </p>
      ) : null}
    </section>
  )
}
