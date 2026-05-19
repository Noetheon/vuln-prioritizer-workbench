import { VpwBadge } from "./VpwBadge"
import type { VpwDataTableColumn } from "./VpwDataTable"

type ShowcaseFinding = {
  id: string
  priority: "critical" | "high" | "medium"
  evidence: string
  decision: string
}

export const findingRows: ShowcaseFinding[] = [
  {
    id: "CVE-2024-3094",
    priority: "critical",
    evidence: "KEV, EPSS, asset exposure",
    decision: "Patch now",
  },
  {
    id: "CVE-2023-34362",
    priority: "high",
    evidence: "VEX occurrence evidence",
    decision: "Validate scope",
  },
  {
    id: "CVE-2021-44228",
    priority: "medium",
    evidence: "Provider snapshot",
    decision: "Monitor",
  },
]

export const findingColumns: VpwDataTableColumn<ShowcaseFinding>[] = [
  {
    id: "id",
    header: "Finding",
    cell: (row) => <span className="font-mono text-xs">{row.id}</span>,
  },
  {
    id: "priority",
    header: "Priority",
    cell: (row) => (
      <VpwBadge tone={row.priority === "critical" ? "critical" : "warning"}>
        {row.priority}
      </VpwBadge>
    ),
  },
  { id: "evidence", header: "Evidence", cell: (row) => row.evidence },
  { id: "decision", header: "Decision", cell: (row) => row.decision },
]
