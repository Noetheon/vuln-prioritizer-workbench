import { formatDateTime as formatWorkbenchDateTime } from "../../lib/date-format.ts"

export function formatDateTime(value: string | null | undefined) {
  return formatWorkbenchDateTime(value)
}
