import { Link } from "@/lib/router"
import { Button } from "@/components/ui/button"
import {
  VpwKeyValueList,
  VpwPanel,
  VpwSectionHeader,
} from "@/components/vpw"
import type { ImportRunSummary } from "./ImportRunDetailTabShared"

export function FindingsTab({ summary }: { summary: ImportRunSummary }) {
  const findingsCount =
    summary.finding_count ??
    (summary.created_findings ?? 0) + (summary.updated_findings ?? 0)
  if (findingsCount <= 0) {
    return (
      <VpwPanel className="flex flex-col gap-4">
        <VpwSectionHeader
          description="Parser diagnostics may explain why this import did not create or update findings."
          title="No findings created"
        />
        <div className="flex flex-wrap gap-2">
          <Button asChild>
            <Link search={{ projectId: summary.project_id }} to="/findings">
              Open Triage
            </Link>
          </Button>
        </div>
      </VpwPanel>
    )
  }
  return (
    <VpwPanel className="flex flex-col gap-4">
      <VpwSectionHeader
        description={`This run created ${summary.created_findings ?? 0} and updated ${
          summary.updated_findings ?? 0
        } findings. Open Triage with project context preserved to review and prioritize the results.`}
        title="Findings are ready for triage"
      />
      <VpwKeyValueList
        columns={2}
        density="compact"
        items={[
          { label: "Total findings", value: findingsCount },
          { label: "Created", value: summary.created_findings ?? 0 },
          { label: "Updated", value: summary.updated_findings ?? 0 },
          { label: "Ignored lines", value: summary.ignored_lines ?? 0 },
        ]}
      />
      <div className="flex flex-wrap gap-2">
        <Button asChild>
          <Link search={{ projectId: summary.project_id }} to="/findings">
            Open Triage
          </Link>
        </Button>
      </div>
    </VpwPanel>
  )
}
