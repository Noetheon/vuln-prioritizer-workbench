import type { FindingPublic } from "@/api-client"
import { VpwBadge } from "@/components/vpw"
import { slaDueSummary } from "@/lib/finding-sla-due"

export function SlaDueBadge({
  finding,
  overflow = "truncate",
}: {
  finding: Pick<FindingPublic, "sla_due_at" | "sla_state">
  overflow?: "truncate" | "wrap"
}) {
  const due = slaDueSummary(finding)
  if (!due) return null
  return (
    <VpwBadge
      density="compact"
      overflow={overflow}
      title={due.title}
      tone={due.tone}
    >
      {due.label}
    </VpwBadge>
  )
}
